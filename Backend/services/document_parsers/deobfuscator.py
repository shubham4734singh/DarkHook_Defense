# ================================================================
# deobfuscator.py — DarkHOOK_ Defence
# Version  : 2.0 — Enterprise Macro & Script De-Obfuscator Engine
# Purpose  : Unmasks obfuscated VBA macros, PowerShell payloads,
#            Excel formulas, and PowerPoint scripts to extract real
#            URLs, IPs, dropped executables, and command invocations.
# ================================================================

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List, Set, Tuple


# Common malicious executable extensions
DANGEROUS_EXTENSIONS = (
    ".exe", ".dll", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".scr", ".pif", ".cpl",
    ".iso", ".vhd", ".lnk"
)

# Dangerous system utilities / dropper commands
DANGEROUS_COMMANDS = [
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "bitsadmin", "certutil", "curl", "wget", "rundll32", "regsvr32",
    "schtasks", "wmic", "invoke-webrequest", "iwr", "invoke-expression",
    "iex", "downloadstring", "downloadfile", "urldownloadtofile",
    "shellexecute", "wscript.shell", "shell.application"
]


def _is_valid_printable(text: str) -> bool:
    """Return True if text consists mostly of printable ASCII characters."""
    if not text:
        return False
    printable_count = sum(1 for ch in text if 32 <= ord(ch) <= 126 or ch in "\r\n\t")
    return (printable_count / len(text)) >= 0.85


def deobfuscate_chr_concatenations(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Evaluates Chr(x) & Chr(y) / ChrW(x) / Char(x) concatenation chains.
    Example: Chr(104) & Chr(116) & Chr(116) & Chr(112) -> 'http'
             "ht" & Chr(116) & "p://evil.com" -> 'http://evil.com'
    """
    transformed = code
    findings: List[Dict[str, Any]] = []

    # Pattern for continuous Chr(...) / string & chains
    chr_chain_pattern = re.compile(
        r'(?:(?:ChrW?|Char)\s*\(\s*\d+\s*\)|"[^"\n\r]*")(?:\s*[\&\+]\s*(?:(?:ChrW?|Char)\s*\(\s*\d+\s*\)|"[^"\n\r]*"))+',
        re.IGNORECASE
    )

    for match in chr_chain_pattern.finditer(code):
        matched_str = match.group(0)
        if not re.search(r'(?:ChrW?|Char)\s*\(\s*\d+\s*\)', matched_str, re.IGNORECASE):
            continue

        parts = re.split(r'\s*[\&\+]\s*', matched_str)
        decoded_chars = []
        valid_chain = True

        for part in parts:
            part = part.strip()
            chr_m = re.match(r'^(?:ChrW?|Char)\s*\(\s*(\d+)\s*\)$', part, re.IGNORECASE)
            if chr_m:
                val = int(chr_m.group(1))
                if 0 <= val <= 65535:
                    decoded_chars.append(chr(val))
                else:
                    valid_chain = False
                    break
            elif part.startswith('"') and part.endswith('"') and len(part) >= 2:
                decoded_chars.append(part[1:-1])
            else:
                valid_chain = False
                break

        if valid_chain and decoded_chars:
            unmasked = "".join(decoded_chars)
            if len(unmasked) >= 3 and _is_valid_printable(unmasked):
                findings.append({
                    "type": "chr_concatenation",
                    "original": matched_str[:120],
                    "unmasked": unmasked,
                })
                transformed = transformed.replace(matched_str, f'"{unmasked}"')

    return transformed, findings


def deobfuscate_str_reverse(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Evaluates StrReverse("...") calls.
    Example: StrReverse("exe.rotavitca/moc.kcatta//:ptth") -> 'http://attack.com/activator.exe'
    """
    transformed = code
    findings: List[Dict[str, Any]] = []

    rev_pattern = re.compile(r'StrReverse\s*\(\s*"([^"\n\r]*)"\s*\)', re.IGNORECASE)

    for match in rev_pattern.finditer(code):
        matched_str = match.group(0)
        inner_str = match.group(1)
        unmasked = inner_str[::-1]

        if len(unmasked) >= 3:
            findings.append({
                "type": "str_reverse",
                "original": matched_str[:120],
                "unmasked": unmasked,
            })
            transformed = transformed.replace(matched_str, f'"{unmasked}"')

    return transformed, findings


def deobfuscate_split_strings(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Combines fragmented string literals concatenated by & or +.
    Example: "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" -> 'powershell'
    """
    transformed = code
    findings: List[Dict[str, Any]] = []

    concat_pattern = re.compile(
        r'"([^"\n\r]{1,10})"(?:\s*[\&\+]\s*"([^"\n\r]{1,10})"){2,}',
        re.IGNORECASE
    )

    for match in concat_pattern.finditer(code):
        matched_str = match.group(0)
        tokens = re.findall(r'"([^"\n\r]*)"', matched_str)
        if len(tokens) >= 3:
            unmasked = "".join(tokens)
            if len(unmasked) >= 4 and _is_valid_printable(unmasked):
                findings.append({
                    "type": "split_strings",
                    "original": matched_str[:120],
                    "unmasked": unmasked,
                })
                transformed = transformed.replace(matched_str, f'"{unmasked}"')

    return transformed, findings


def deobfuscate_string_replace(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Evaluates Replace("target", "find", "replaceWith") calls commonly used to break keywords.
    Example: Replace("c!m!d!.!e!x!e", "!", "") -> 'cmd.exe'
             Replace("httpXXevil.com", "XX", "://") -> 'http://evil.com'
    """
    transformed = code
    findings: List[Dict[str, Any]] = []

    replace_pattern = re.compile(
        r'Replace\s*\(\s*"([^"\n\r]*)"\s*,\s*"([^"\n\r]*)"\s*,\s*"([^"\n\r]*)"\s*\)',
        re.IGNORECASE
    )

    for match in replace_pattern.finditer(code):
        matched_str = match.group(0)
        src = match.group(1)
        find = match.group(2)
        repl = match.group(3)

        unmasked = src.replace(find, repl)
        if len(unmasked) >= 3 and _is_valid_printable(unmasked):
            findings.append({
                "type": "string_replace",
                "original": matched_str[:120],
                "unmasked": unmasked,
            })
            transformed = transformed.replace(matched_str, f'"{unmasked}"')

    return transformed, findings


def deobfuscate_env_vars(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Normalizes VBA Environ("...") calls and Windows %VAR% references.
    Example: Environ("TEMP") & "\\payload.exe" -> '%TEMP%\\payload.exe'
    """
    transformed = code
    findings: List[Dict[str, Any]] = []

    environ_pattern = re.compile(r'Environ\s*\(\s*"([^"\n\r]+)"\s*\)', re.IGNORECASE)
    for match in environ_pattern.finditer(code):
        matched_str = match.group(0)
        var_name = match.group(1).upper()
        unmasked = f"%{var_name}%"
        findings.append({
            "type": "environ_var",
            "original": matched_str,
            "unmasked": unmasked,
        })
        transformed = transformed.replace(matched_str, f'"{unmasked}"')

    return transformed, findings


def deobfuscate_powershell_encoded_command(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Extracts and decodes PowerShell -EncodedCommand / -enc / -e Base64 Unicode payloads.
    Example: powershell.exe -enc SQBFAFgA... -> IEX(New-Object Net.WebClient)...
    """
    findings: List[Dict[str, Any]] = []
    
    ps_enc_pattern = re.compile(
        r'(?:-|/)(?:e|enc|encodedcommand)\s+(?:["\']?)([A-Za-z0-9+/=]{16,})(?:["\']?)',
        re.IGNORECASE
    )

    for match in ps_enc_pattern.finditer(code):
        matched_str = match.group(0)
        b64_str = match.group(1)

        # Pad if missing
        pad_len = len(b64_str) % 4
        if pad_len:
            b64_str += "=" * (4 - pad_len)

        try:
            raw_bytes = base64.b64decode(b64_str)
            decoded = ""
            try:
                decoded = raw_bytes.decode("utf-16le")
            except UnicodeDecodeError:
                decoded = raw_bytes.decode("utf-8", errors="ignore")

            if _is_valid_printable(decoded) and len(decoded) >= 4:
                findings.append({
                    "type": "powershell_encoded_command",
                    "original": matched_str[:120],
                    "unmasked": decoded,
                    "is_threat_payload": True,
                })
        except Exception:
            continue

    return code, findings


def deobfuscate_base64_payloads(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Extracts and decodes embedded Base64 strings (UTF-8, UTF-16LE / PowerShell encoded commands).
    """
    findings: List[Dict[str, Any]] = []
    candidate_pattern = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')

    for match in candidate_pattern.finditer(code):
        b64_str = match.group(0)
        if len(b64_str) % 4 != 0:
            continue

        try:
            raw_bytes = base64.b64decode(b64_str, validate=True)
            if len(raw_bytes) < 8:
                continue

            decoded_text = ""
            # Check UTF-16LE first (PowerShell -EncodedCommand standard)
            try:
                utf16_candidate = raw_bytes.decode("utf-16le")
                if _is_valid_printable(utf16_candidate) and len(utf16_candidate) >= 6:
                    decoded_text = utf16_candidate
            except UnicodeDecodeError:
                pass

            # If not UTF-16LE, try UTF-8
            if not decoded_text:
                try:
                    utf8_candidate = raw_bytes.decode("utf-8")
                    if _is_valid_printable(utf8_candidate) and len(utf8_candidate) >= 6:
                        decoded_text = utf8_candidate
                except UnicodeDecodeError:
                    pass

            if decoded_text:
                lower_decoded = decoded_text.lower()
                is_threat_payload = any(cmd in lower_decoded for cmd in DANGEROUS_COMMANDS) or (
                    "http://" in lower_decoded or "https://" in lower_decoded
                ) or any(lower_decoded.endswith(ext) for ext in DANGEROUS_EXTENSIONS)

                findings.append({
                    "type": "base64_payload",
                    "original": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                    "unmasked": decoded_text[:300],
                    "is_threat_payload": is_threat_payload,
                })
        except (binascii.Error, ValueError):
            continue

    return code, findings


def deobfuscate_hex_payloads(code: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Decodes formatted hex sequences such as &H48&H65&H78 or 0x48, 0x65, ...
    """
    findings: List[Dict[str, Any]] = []

    hex_series_pattern = re.compile(
        r'(?:(?:&H|0x)[0-9a-fA-F]{1,2}(?:\s*,\s*|\s*[\&\+]\s*)){3,}(?:&H|0x)[0-9a-fA-F]{1,2}',
        re.IGNORECASE
    )

    for match in hex_series_pattern.finditer(code):
        matched_str = match.group(0)
        tokens = re.findall(r'(?:&H|0x)([0-9a-fA-F]{1,2})', matched_str, re.IGNORECASE)
        try:
            byte_vals = bytes(int(tok, 16) for tok in tokens)
            decoded = byte_vals.decode("latin-1", errors="ignore")
            if _is_valid_printable(decoded) and len(decoded) >= 4:
                findings.append({
                    "type": "hex_byte_series",
                    "original": matched_str[:80],
                    "unmasked": decoded,
                })
        except Exception:
            continue

    return code, findings


def extract_hidden_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extracts Indicators of Compromise (IOCs) from de-obfuscated text:
    - URLs
    - IPv4 addresses
    - Suspicious executable/payload drops
    - Suspicious commands invoked
    """
    # 1. URL extraction
    raw_urls = re.findall(r'https?://[^\s"\'<>{}|\\^`\[\]]+', text, re.IGNORECASE)
    cleaned_urls: Set[str] = set()
    for u in raw_urls:
        u_clean = u.rstrip(".,;)\"'>")
        if len(u_clean) > 8:
            cleaned_urls.add(u_clean)

    # 2. IPv4 extraction
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    raw_ips = ip_pattern.findall(text)
    valid_ips: Set[str] = set()
    for ip in raw_ips:
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            if not ip.startswith("127.") and ip != "0.0.0.0":
                valid_ips.add(ip)

    # 3. Executable / Dropped payload filenames
    exec_pattern = re.compile(
        r'[a-zA-Z0-9_\-\\]+\.(?:exe|dll|vbs|vbe|js|ps1|bat|cmd|hta|scr|iso|lnk)',
        re.IGNORECASE
    )
    dropped_files = set(exec_pattern.findall(text))

    # 4. Commands detected
    commands_found: Set[str] = set()
    lower_text = text.lower()
    for cmd in DANGEROUS_COMMANDS:
        if re.search(r'\b' + re.escape(cmd) + r'\b', lower_text):
            commands_found.add(cmd)

    return {
        "urls": sorted(cleaned_urls),
        "ips": sorted(valid_ips),
        "dropped_files": sorted(dropped_files),
        "commands": sorted(commands_found),
    }


def run_deobfuscation_pipeline(raw_script: str) -> Dict[str, Any]:
    """
    Main orchestration entry point: runs the complete multi-layer deobfuscation
    pipeline on any macro code or formula text.

    Returns:
      - deobfuscation_applied: bool
      - transformations: List of decoded items
      - unmasked_code_sample: str
      - iocs: {urls, ips, dropped_files, commands}
      - new_findings: List of string keys for scorer.py
      - details: List of human-readable log strings
    """
    if not raw_script or len(raw_script.strip()) == 0:
        return {
            "deobfuscation_applied": False,
            "transformations": [],
            "iocs": {"urls": [], "ips": [], "dropped_files": [], "commands": []},
            "new_findings": [],
            "details": [],
        }

    working_code = raw_script
    all_transformations: List[Dict[str, Any]] = []
    details: List[str] = []
    new_findings: List[str] = []

    # Step 1: Chr() and ChrW() Concatenation
    working_code, chr_finds = deobfuscate_chr_concatenations(working_code)
    if chr_finds:
        all_transformations.extend(chr_finds)
        new_findings.append("chr_obfuscation_detected")
        for f in chr_finds[:5]:
            details.append(f"🔓 De-Obfuscated Chr() Code: '{f['original']}' ➔ '{f['unmasked']}'")

    # Step 2: String Reversal (StrReverse)
    working_code, rev_finds = deobfuscate_str_reverse(working_code)
    if rev_finds:
        all_transformations.extend(rev_finds)
        new_findings.append("reverse_string_obfuscation")
        for f in rev_finds[:5]:
            details.append(f"🔓 Unmasked StrReverse: '{f['original']}' ➔ '{f['unmasked']}'")

    # Step 3: Split String Joins ("p" & "o" & "w" & "e" & "r")
    working_code, split_finds = deobfuscate_split_strings(working_code)
    if split_finds:
        all_transformations.extend(split_finds)
        for f in split_finds[:5]:
            details.append(f"🔓 Joined Split Tokens: '{f['original']}' ➔ '{f['unmasked']}'")

    # Step 4: String Replace evaluation
    working_code, repl_finds = deobfuscate_string_replace(working_code)
    if repl_finds:
        all_transformations.extend(repl_finds)
        new_findings.append("string_obfuscation")
        for f in repl_finds[:5]:
            details.append(f"🔓 Unmasked Replace(): '{f['original']}' ➔ '{f['unmasked']}'")

    # Step 5: Environ variables
    working_code, env_finds = deobfuscate_env_vars(working_code)
    if env_finds:
        all_transformations.extend(env_finds)

    # Step 6: PowerShell Encoded Commands
    _, ps_enc_finds = deobfuscate_powershell_encoded_command(raw_script)
    if ps_enc_finds:
        all_transformations.extend(ps_enc_finds)
        new_findings.append("powershell_encoded_command")
        for f in ps_enc_finds:
            details.append(f"🚨 Decoded PowerShell -EncodedCommand: {f['unmasked'][:120]}...")

    # Step 7: Base64 Payloads
    _, b64_finds = deobfuscate_base64_payloads(raw_script)
    if b64_finds:
        all_transformations.extend(b64_finds)
        for f in b64_finds:
            if f.get("is_threat_payload"):
                new_findings.append("deobfuscated_powershell_payload")
                details.append(f"🚨 Unmasked Base64 Threat Payload: {f['unmasked'][:120]}...")
            else:
                details.append(f"🔓 Decoded Base64 String: {f['unmasked'][:80]}")

    # Step 8: Hex series
    _, hex_finds = deobfuscate_hex_payloads(raw_script)
    if hex_finds:
        all_transformations.extend(hex_finds)
        for f in hex_finds:
            details.append(f"🔓 Decoded Hex Payload: '{f['unmasked']}'")

    # Step 9: Extract all hidden IOCs from both raw and unmasked code
    full_text_to_scan = f"{raw_script}\n{working_code}\n" + "\n".join(
        t.get("unmasked", "") for t in all_transformations
    )
    iocs = extract_hidden_iocs(full_text_to_scan)

    # Classify IOC findings for scorer
    if iocs["urls"]:
        new_findings.append("deobfuscated_malicious_url")
        for u in iocs["urls"]:
            details.append(f"🎯 Discovered Hidden C2 / Download URL: {u}")

    if iocs["dropped_files"]:
        new_findings.append("deobfuscated_executable_drop")
        for d in iocs["dropped_files"]:
            details.append(f"⚠️ Unmasked Executable / Dropper Payload: {d}")

    if any("powershell" in c or "cmd" in c or "iex" in c for c in iocs["commands"]):
        if "deobfuscated_powershell_payload" not in new_findings:
            new_findings.append("deobfuscated_powershell_payload")

    deob_applied = len(all_transformations) > 0 or any(len(v) > 0 for v in iocs.values())

    return {
        "deobfuscation_applied": deob_applied,
        "transformations_count": len(all_transformations),
        "transformations": all_transformations,
        "unmasked_code_sample": working_code[:500] if deob_applied else "",
        "iocs": iocs,
        "new_findings": list(set(new_findings)),
        "details": details,
    }
