import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
from core.sql_database import SessionLocal, init_sqlite_db
from models.scan_history import ScanHistory


class ScanHistoryRepository:
    """Repository for persisting and querying scan history and dashboard metrics."""

    def __init__(self):
        self._tables_initialized = False

    def _ensure_tables(self):
        if not self._tables_initialized:
            try:
                init_sqlite_db()
                self._tables_initialized = True
            except Exception as e:
                print(f"[DASHBOARD WARNING] Table initialization check failed: {e}")

    def save_scan(self, scan_data: dict) -> ScanHistory | None:
        """
        Save a completed scan result into scan_history table.
        Wrapped in try/except to prevent database errors from affecting scan responses.
        """
        self._ensure_tables()
        db = None
        try:
            db = SessionLocal()
            file_name = str(scan_data.get("fileName") or scan_data.get("file_name") or "unknown_file")
            file_hash = str(scan_data.get("fileHash") or scan_data.get("file_hash") or "")
            risk_score = int(scan_data.get("riskScore") if scan_data.get("riskScore") is not None else scan_data.get("risk_score", 0))
            verdict = str(scan_data.get("verdict") or "Safe").strip().capitalize()
            threat_count = int(scan_data.get("totalFindings") if scan_data.get("totalFindings") is not None else scan_data.get("threat_count", 0))
            scan_duration = float(scan_data.get("scanTime") if scan_data.get("scanTime") is not None else scan_data.get("scan_duration", 0.0))

            # Extracted URLs count calculation
            extracted_urls = scan_data.get("extractedUrls") or scan_data.get("extracted_urls") or []
            if isinstance(extracted_urls, list):
                extracted_url_count = len(extracted_urls)
            else:
                extracted_url_count = int(scan_data.get("extracted_url_count", 0))

            # Raw finding IDs list extraction
            findings_raw = scan_data.get("findings") or []
            if not findings_raw and isinstance(scan_data.get("findingsDetailed"), list):
                findings_raw = [
                    f.get("findingType") or f.get("finding_type") or f.get("name")
                    for f in scan_data.get("findingsDetailed", [])
                    if isinstance(f, dict)
                ]
            findings_json = json.dumps([f for f in findings_raw if f])

            record = ScanHistory(
                file_name=file_name,
                file_hash=file_hash,
                risk_score=risk_score,
                verdict=verdict,
                threat_count=threat_count,
                scan_duration=scan_duration,
                extracted_url_count=extracted_url_count,
                findings=findings_json,
                scanned_at=datetime.now(timezone.utc)
            )

            db.add(record)
            db.commit()
            db.refresh(record)

            print(
                f"[DASHBOARD] Saved scan history for {record.file_name} "
                f"(ID: {record.id}, Score: {record.risk_score}, Verdict: {record.verdict})"
            )
            return record
        except Exception as exc:
            if db:
                try:
                    db.rollback()
                except Exception:
                    pass
            print(f"[DASHBOARD ERROR] Failed to save scan history: {exc}")
            return None
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

    def get_stats(self) -> dict:
        """
        Get aggregated scan statistics for dashboard.
        """
        self._ensure_tables()
        db = None
        try:
            db = SessionLocal()
            total_scans = db.query(func.count(ScanHistory.id)).scalar() or 0

            if total_scans == 0:
                return {
                    "total_scans": 0,
                    "phishing_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "average_risk_score": 0.0,
                    "most_common_finding": None,
                    "scans_today": 0,
                }

            all_records = db.query(ScanHistory).all()

            phishing_count = 0
            suspicious_count = 0
            safe_count = 0
            total_score = 0
            findings_counter = Counter()

            now_utc = datetime.now(timezone.utc)
            today_utc_date = now_utc.date()
            scans_today = 0

            for rec in all_records:
                v_lower = rec.verdict.lower() if rec.verdict else "safe"
                if v_lower in ("phishing", "malicious"):
                    phishing_count += 1
                elif v_lower == "suspicious":
                    suspicious_count += 1
                else:
                    safe_count += 1

                total_score += rec.risk_score

                # Findings count
                f_list = rec.get_findings_list()
                for item in f_list:
                    if item:
                        findings_counter[str(item)] += 1

                # Scans today count
                if rec.scanned_at:
                    rec_date = rec.scanned_at.date() if hasattr(rec.scanned_at, "date") else None
                    if rec_date == today_utc_date:
                        scans_today += 1

            avg_score = round(total_score / total_scans, 1)
            most_common = findings_counter.most_common(1)
            most_common_finding = most_common[0][0] if most_common else None

            return {
                "total_scans": total_scans,
                "phishing_count": phishing_count,
                "suspicious_count": suspicious_count,
                "safe_count": safe_count,
                "average_risk_score": avg_score,
                "most_common_finding": most_common_finding,
                "scans_today": scans_today,
            }
        except Exception as exc:
            print(f"[DASHBOARD ERROR] Failed to fetch stats: {exc}")
            return {
                "total_scans": 0,
                "phishing_count": 0,
                "suspicious_count": 0,
                "safe_count": 0,
                "average_risk_score": 0.0,
                "most_common_finding": None,
                "scans_today": 0,
            }
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

    def get_recent(self, limit: int = 50) -> list[dict]:
        """
        Fetch recent scans across all modules (URLs, Documents, Emails),
        merging SQLite scan history and MongoDB URL cache repository.
        """
        self._ensure_tables()
        all_results = []
        seen_keys = set()

        # 1. Fetch from SQLite ScanHistory table
        db = None
        try:
            db = SessionLocal()
            records = (
                db.query(ScanHistory)
                .order_by(ScanHistory.scanned_at.desc())
                .limit(limit)
                .all()
            )
            for r in records:
                fn = r.file_name or ""
                st = "URL" if (fn.startswith("http://") or fn.startswith("https://") or fn.startswith("www.")) else ("EMAIL" if fn.endswith(".eml") else "DOCUMENT")
                item = {
                    "id": f"sql_{r.id}",
                    "file_name": fn,
                    "url": fn,
                    "scan_type": st,
                    "verdict": r.verdict,
                    "status": r.verdict,
                    "risk_score": r.risk_score,
                    "score": r.risk_score,
                    "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
                    "raw_timestamp": r.scanned_at,
                    "file_hash": r.file_hash,
                    "threat_count": r.threat_count,
                    "flags": r.get_findings_list(),
                    "explanation": f"Audit entry logged with verdict {r.verdict} ({r.risk_score}/100)",
                }
                dedup_key = f"{st}_{fn.lower()}_{r.scanned_at.isoformat() if r.scanned_at else ''}"
                seen_keys.add(dedup_key)
                all_results.append(item)
        except Exception as exc:
            print(f"[DASHBOARD ERROR] Failed to fetch SQLite scan history: {exc}")
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

        # 2. Fetch from URL Cache Repository (MongoDB / in-memory cache)
        try:
            from repositories.url_cache_repository import url_cache_repository
            cached_urls = url_cache_repository.get_history(limit=limit)
            for cu in cached_urls:
                target_url = cu.get("url", "")
                res = cu.get("result", {})
                sc_at = cu.get("scanned_at")
                sc_at_iso = sc_at.isoformat() if isinstance(sc_at, datetime) else str(sc_at or "")

                dedup_key = f"URL_{target_url.lower()}_{sc_at_iso}"
                if dedup_key in seen_keys:
                    continue

                item = {
                    "id": f"url_{cu.get('_id', target_url)}",
                    "file_name": target_url,
                    "url": target_url,
                    "scan_type": "URL",
                    "verdict": res.get("verdict", "Safe"),
                    "status": res.get("status", "safe"),
                    "risk_score": res.get("score", 0),
                    "score": res.get("score", 0),
                    "scanned_at": sc_at_iso,
                    "raw_timestamp": sc_at if isinstance(sc_at, datetime) else None,
                    "file_hash": "",
                    "threat_count": len(res.get("flags", [])),
                    "flags": res.get("flags", []),
                    "explanation": res.get("explanation", ""),
                    "feature_summary": res.get("feature_summary", {}),
                    "analysis_details": res.get("analysis_details", {}),
                    "screenshot": res.get("screenshot"),
                }
                all_results.append(item)
        except Exception as cu_exc:
            print(f"[DASHBOARD WARNING] Failed merging URL cache history: {cu_exc}")

        # 3. Sort merged list by timestamp descending
        def get_sort_key(x):
            ts = x.get("raw_timestamp")
            if ts:
                return ts.timestamp() if hasattr(ts, "timestamp") else 0
            if x.get("scanned_at"):
                try:
                    return datetime.fromisoformat(x["scanned_at"].replace("Z", "+00:00")).timestamp()
                except Exception:
                    pass
            return 0

        all_results.sort(key=get_sort_key, reverse=True)
        return all_results[:limit]

    def get_daily_trend(self, days: int = 7) -> list[dict]:
        """
        Get scan counts grouped by day for the last N days, broken down by verdict.
        """
        self._ensure_tables()
        db = None
        try:
            db = SessionLocal()
            days = max(1, min(days, 90))
            now_utc = datetime.now(timezone.utc)
            start_date = (now_utc - timedelta(days=days - 1)).date()

            # Initialize date bucket map
            date_map = {}
            for i in range(days):
                d_str = (start_date + timedelta(days=i)).isoformat()
                date_map[d_str] = {"date": d_str, "phishing": 0, "suspicious": 0, "safe": 0}

            records = db.query(ScanHistory).all()
            for rec in records:
                if rec.scanned_at:
                    rec_date_str = rec.scanned_at.date().isoformat()
                    if rec_date_str in date_map:
                        v_lower = rec.verdict.lower() if rec.verdict else "safe"
                        if v_lower in ("phishing", "malicious"):
                            date_map[rec_date_str]["phishing"] += 1
                        elif v_lower == "suspicious":
                            date_map[rec_date_str]["suspicious"] += 1
                        else:
                            date_map[rec_date_str]["safe"] += 1

            return list(date_map.values())
        except Exception as exc:
            print(f"[DASHBOARD ERROR] Failed to fetch daily trend: {exc}")
            return []
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass


scan_history_repository = ScanHistoryRepository()
