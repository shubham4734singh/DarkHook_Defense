from fastapi import APIRouter, Query
from repositories.scan_history_repository import scan_history_repository

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats():
    """
    Retrieve live aggregated scan statistics (total scans, verdict counts, avg score, scans today).
    """
    return scan_history_repository.get_stats()


@router.get("/recent")
async def get_recent_scans(limit: int = Query(10, ge=1, le=100)):
    """
    Retrieve the most recent N document scan records (sorted newest first).
    """
    return scan_history_repository.get_recent(limit=limit)


@router.get("/daily-trend")
async def get_daily_trend(days: int = Query(7, ge=1, le=90)):
    """
    Retrieve scan counts grouped by day for the last N days broken down by verdict.
    """
    return scan_history_repository.get_daily_trend(days=days)
