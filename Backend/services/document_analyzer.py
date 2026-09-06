import hashlib
import importlib
import io
import os
import re
import tempfile
import zipfile
from time import perf_counter
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from services.document_parsers.scorer import MITRE_MAP, WEIGHTS, calculate_score

SUPPORTED_PARSERS: Dict[str, Tuple[str, str, str, str]] = {
    # PDF
    ".pdf": ("PDF", "Portable Document Format", "services.document_parsers.pdf_parser", "parse_pdf"),

    # Word Formats
    ".docx": ("Word", "Microsoft Word Document", "services.document_parsers.docx_parser", "parse_docx"),
    ".docm": ("Word", "Microsoft Word Macro-Enabled Document", "services.document_parsers.docx_parser", "parse_docx"),
    ".dotx": ("Word", "Microsoft Word Template", "services.document_parsers.docx_parser", "parse_docx"),
    ".dotm": ("Word", "Microsoft Word Macro-Enabled Template", "services.document_parsers.docx_parser", "parse_docx"),
    ".doc": ("Word", "Microsoft Word Document (legacy OLE)", "services.document_parsers.docx_parser", "parse_docx"),
    ".rtf": ("Word", "Rich Text Format Document", "services.document_parsers.docx_parser", "parse_docx"),

    # Excel Formats
    ".xlsx": ("Excel", "Microsoft Excel Spreadsheet", "services.document_parsers.excel_parser", "parse_excel"),
    ".xlsm": ("Excel", "Microsoft Excel Macro-Enabled Spreadsheet", "services.document_parsers.excel_parser", "parse_excel"),
    ".xlsb": ("Excel", "Microsoft Excel Binary Spreadsheet", "services.document_parsers.excel_parser", "parse_excel"),
    ".xltx": ("Excel", "Microsoft Excel Template", "services.document_parsers.excel_parser", "parse_excel"),
    ".xltm": ("Excel", "Microsoft Excel Macro-Enabled Template", "services.document_parsers.excel_parser", "parse_excel"),
    ".xls": ("Excel", "Microsoft Excel Spreadsheet (legacy)", "services.document_parsers.excel_parser", "parse_excel"),

    # PowerPoint Formats
    ".pptx": ("PowerPoint", "Microsoft PowerPoint Presentation", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".ppt": ("PowerPoint", "Microsoft PowerPoint Presentation (legacy)", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".pps": ("PowerPoint", "Microsoft PowerPoint Slideshow", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".ppsx": ("PowerPoint", "Microsoft PowerPoint Slideshow", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".pptm": ("PowerPoint", "Microsoft PowerPoint Macro-Enabled Presentation", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".ppsm": ("PowerPoint", "Microsoft PowerPoint Macro-Enabled Slideshow", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".potx": ("PowerPoint", "Microsoft PowerPoint Template", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".potm": ("PowerPoint", "Microsoft PowerPoint Macro-Enabled Template", "services.document_parsers.ppt_parser", "parse_ppt"),

    # Image / OCR Formats
    ".png": ("Image", "Portable Network Graphics", "services.document_parsers.ocr_parser", "parse_image"),
    ".jpg": ("Image", "JPEG image", "services.document_parsers.ocr_parser", "parse_image"),
    ".jpeg": ("Image", "JPEG image", "services.document_parsers.ocr_parser", "parse_image"),
    ".webp": ("Image", "WebP image", "services.document_parsers.ocr_parser", "parse_image"),
    ".bmp": ("Image", "Bitmap image", "services.document_parsers.ocr_parser", "parse_image"),
    ".tif": ("Image", "TIFF image", "services.document_parsers.ocr_parser", "parse_image"),
    ".tiff": ("Image", "TIFF image", "services.document_parsers.ocr_parser", "parse_image"),
}

MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB max uncompressed
MAX_ZIP_ENTRIES = 1000
MAX_COMPRESSION_RATIO = 100


def get_file_hash(file_data: bytes) -> str:
    return hashlib.sha256(file_data).hexdigest()


def detect_file_magic(file_data: bytes) -> str:
    """Inspects raw header magic bytes to detect true file format."""
    if len(file_data) < 4:
        return "unknown"
    if file_data.startswith(b"%PDF-"):
        return "pdf"
    if file_data.startswith(b"PK\x03\x04"):
        return "zip_ooxml"
    if file_data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole_binary"
    if file_data.startswith(b"{\\rtf"):
        return "rtf"
    if file_data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if file_data.startswith(b"\xFF\xD8\xFF"):
        return "jpeg"
    if file_data.startswith(b"GIF8"):
        return "gif"
    if file_data.startswith(b"BM"):
        return "bmp"
    if len(file_data) >= 12 and file_data.startswith(b"RIFF") and file_data[8:12] == b"WEBP":
        return "webp"
    if file_data.startswith(b"MZ"):
        return "executable_pe"
    if file_data.startswith(b"\x7fELF"):
        return "executable_elf"
    return "unknown"


def validate_archive_safety(file_data: bytes) -> List[str]:
    """Validates zip archives against decompression bombs, path traversal, and malicious entry counts."""
    findings: List[str] = []
    try:
        if zipfile.is_zipfile(io.BytesIO(file_data)):
            with zipfile.ZipFile(io.BytesIO(file_data)) as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ZIP_ENTRIES:
                    findings.append("suspicious_zip_bomb")
                    return findings

                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    findings.append("suspicious_zip_bomb")
                    return findings

                compressed_size = max(len(file_data), 1)
                if (total_uncompressed / compressed_size) > MAX_COMPRESSION_RATIO and total_uncompressed > 5 * 1024 * 1024:
                    findings.append("suspicious_zip_bomb")
                    return findings

                for info in infolist:
                    if ".." in info.filename or info.filename.startswith("/") or info.filename.startswith("\\"):
                        findings.append("corrupted_structure")
                        break
    except Exception:
        findings.append("malformed_zip")
    return findings


def extract_and_score_urls(details: List[str], findings: List[str]) -> List[Dict[str, Any]]:
    """Extracts all URLs mentioned in scan details and assigns safety status and threat reasoning."""
    url_pattern = re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]+', re.IGNORECASE)
    seen_urls: set[str] = set()
    results: List[Dict[str, Any]] = []

    text_corpus = "\n".join(details)
    extracted = url_pattern.findall(text_corpus)

    for raw_url in extracted:
        u_clean = raw_url.rstrip(".,;)\"'>")
        if len(u_clean) <= 8 or u_clean in seen_urls:
            continue
        seen_urls.add(u_clean)

        parsed = urlparse(u_clean)
        domain = parsed.hostname or ""
        reasons: List[str] = []
        is_suspicious = False

        # TLD check
        tld = domain.split(".")[-1].lower() if "." in domain else ""
        if tld in {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "country", "loan", "win", "icu"}:
            is_suspicious = True
            reasons.append(f"Suspicious top-level domain (.{tld})")

        # IP host check
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
            is_suspicious = True
            reasons.append("Direct IP address destination")

        # @ trick
        if "@" in u_clean:
            is_suspicious = True
            reasons.append("Contains '@' symbol credential mask")

        # Suspicious keywords in path/domain
        lower_url = u_clean.lower()
        if any(kw in lower_url for kw in ["login", "verify", "secure", "update", "bank", "password", "wallet", "invoice"]):
            reasons.append("Contains credential/phishing keyword")
            if is_suspicious or tld in {"xyz", "top", "click"}:
                is_suspicious = True

        results.append({
            "url": u_clean,
            "domain": domain,
            "is_suspicious": is_suspicious,
            "reasons": reasons if reasons else ["Clean format"],
        })

    return results


def map_severity(finding_type: str) -> str:
    score = WEIGHTS.get(finding_type, 5)
    if score >= 40:
        return "critical"
    if score >= 30:
        return "danger"
    if score >= 15:
        return "warning"
    return "safe"


def _format_file_size_kb(file_size_bytes: int) -> str:
    return f"{file_size_bytes / 1024:.2f} KB"


def _load_parser(module_path: str, function_name: str):
    module = importlib.import_module(module_path)
    return getattr(module, function_name)


class DocumentAnalyzer:
    def get_supported_formats(self) -> list[dict]:
        formats = []
        seen = set()
        for ext, (name, description, _, _) in SUPPORTED_PARSERS.items():
            if ext in seen:
                continue
            seen.add(ext)
            formats.append({
                "name": name,
                "extension": ext,
                "description": f"{description} - Supported",
                "supported": True,
            })
        return formats

    def analyze_document(self, filename: str, file_data: bytes) -> dict:
        """
        Orchestrates safe multi-layer document scanning.
        """
        if not file_data:
            raise ValueError("Uploaded file is empty.")

        suffix = os.path.splitext(filename)[1].lower()
        parser_entry = SUPPORTED_PARSERS.get(suffix)
        if not parser_entry:
            supported = ", ".join(sorted(SUPPORTED_PARSERS.keys()))
            raise ValueError(f"Unsupported file format: {suffix}. Supported formats: {supported}")

        _, _, module_path, function_name = parser_entry
        file_hash = get_file_hash(file_data)
        magic = detect_file_magic(file_data)

        initial_findings: List[str] = []
        initial_details: List[str] = []

        # 1. Check for Disguised Executable Masquerading
        if magic in ("executable_pe", "executable_elf"):
            initial_findings.extend(["file_type_mismatch", "embedded_executable"])
            initial_details.append(f"🚨 CRITICAL: File is a binary executable disguised with a '{suffix}' document extension!")

        # 2. Check Archive / Zip Bomb Safety
        if magic == "zip_ooxml" or suffix in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
            archive_findings = validate_archive_safety(file_data)
            if archive_findings:
                initial_findings.extend(archive_findings)
                if "suspicious_zip_bomb" in archive_findings:
                    initial_details.append("🚨 SECURITY ALERT: High decompression ratio / Zip Bomb indicator detected.")

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_file.write(file_data)
            tmp_path = tmp_file.name

        started = perf_counter()
        try:
            parser_fn = _load_parser(module_path, function_name)
            parse_result = parser_fn(tmp_path) or {}
            
            raw_findings = parse_result.get("findings") or []
            details = parse_result.get("details") or []

            # Combine initial security boundary findings
            findings = initial_findings + raw_findings
            details = initial_details + details

            score_result = calculate_score(findings)

            score_breakdown = []
            for finding_type, item in sorted(
                score_result.get("breakdown", {}).items(),
                key=lambda row: row[1]["score"],
                reverse=True,
            ):
                score_breakdown.append({
                    "finding_type": finding_type.replace("_", " ").title(),
                    "count": item["count"],
                    "score": item["score"],
                })

            findings_detailed = []
            for finding in findings:
                mitre_entry = MITRE_MAP.get(finding)
                findings_detailed.append({
                    "name": finding.replace("_", " ").title(),
                    "findingType": finding,
                    "severity": map_severity(finding),
                    "score": WEIGHTS.get(finding, 5),
                    "mitre": mitre_entry,
                })

            # Extract and inspect URLs
            extracted_urls = extract_and_score_urls(details, findings)

            return {
                "fileName": filename,
                "fileSize": _format_file_size_kb(len(file_data)),
                "fileHash": file_hash,
                "riskScore": score_result["score"],
                "verdict": score_result["verdict"],
                "severity": score_result["severity"],
                "scanTime": round(perf_counter() - started, 4),
                "totalFindings": len(findings),
                "findings": findings,
                "findingsDetailed": findings_detailed,
                "scoreBreakdown": score_breakdown,
                "mitreTechniques": score_result.get("mitre_techniques", []),
                "extractedUrls": extracted_urls,
                "details": details,
            }
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


document_analyzer = DocumentAnalyzer()
