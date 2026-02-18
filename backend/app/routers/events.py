"""Event store endpoints."""
from fastapi import APIRouter, HTTPException

from app.services.event_store import (
    clear_all,
    get_correlated_incidents,
    get_lo2_log_events,
    get_lo2_metric_events,
    get_modsec_events,
    get_summary,
    get_unified_events,
)

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/summary")
async def get_events_summary():
    """Get event counts summary."""
    return get_summary()


@router.get("/modsec")
async def get_modsec_events_endpoint(limit: int = 500):
    """Get ModSecurity events."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    events = get_modsec_events(limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/lo2/log")
async def get_lo2_log_events_endpoint(limit: int = 500):
    """Get LO2 log events."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    events = get_lo2_log_events(limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/lo2/metric")
async def get_lo2_metric_events_endpoint(limit: int = 500):
    """Get LO2 metric events."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    events = get_lo2_metric_events(limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/unified")
async def get_unified_events_endpoint(limit: int = 500):
    """Get unified event timeline (ModSec + LO2 merged, sorted by time)."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    events = get_unified_events(limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/correlated")
async def get_correlated_incidents_endpoint(limit: int = 50):
    """Get correlated incidents (ModSec + LO2 in same 60s window)."""
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200")
    incidents = get_correlated_incidents(limit=limit)
    return {"incidents": incidents, "count": len(incidents)}


@router.post("/clear")
async def clear_events():
    """Clear all event stores."""
    clear_all()
    return {"status": "cleared", "message": "All event stores cleared"}
