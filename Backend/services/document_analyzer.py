import hashlib
import importlib
import os
import tempfile
from time import perf_counter
from typing import Any, Dict, List, Tuple

from services.document_parsers.scorer import WEIGHTS, calculate_score

SUPPORTED_PARSERS: Dict[str, Tuple[str, str, str, str]] = {
    ".pdf": ("PDF", "Portable Document Format", "services.document_parsers.pdf_parser", "parse_pdf"),
    ".docx": ("Word", "Microsoft Word Document", "services.document_parsers.docx_parser", "parse_docx"),
    ".xlsx": ("Excel", "Microsoft Excel Spreadsheet", "services.document_parsers.excel_parser", "parse_excel"),
    ".xls": ("Excel", "Microsoft Excel Spreadsheet (legacy)", "services.document_parsers.excel_parser", "parse_excel"),
    ".pptx": ("PowerPoint", "Microsoft PowerPoint Presentation", "services.document_parsers.ppt_parser", "parse_ppt"),
    ".png": ("Image", "Portable Network Graphics", "services.document_parsers.ocr_parser", "parse_image"),
    ".jpg": ("Image", "JPEG image", "services.document_parsers.ocr_parser", "parse_image"),
    ".jpeg": ("Image", "JPEG image", "services.document_parsers.ocr_parser", "parse_image"),
}

def get_file_hash(file_data: bytes) -> str:
    return hashlib.sha256(file_data).hexdigest()

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
        Orchestrate document scan.
        Raises ValueError on invalid formats/data.
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

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_file.write(file_data)
            tmp_path = tmp_file.name

        started = perf_counter()
        try:
            parser_fn = _load_parser(module_path, function_name)
            parse_result = parser_fn(tmp_path) or {}
            findings = parse_result.get("findings") or []
            details = parse_result.get("details") or []
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
                findings_detailed.append({
                    "name": finding.replace("_", " ").title(),
                    "findingType": finding,
                    "severity": map_severity(finding),
                    "score": WEIGHTS.get(finding, 5),
                })

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
                "details": details,
            }
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

document_analyzer = DocumentAnalyzer()
