"""Event store endpoints."""
from fastapi import APIRouter, HTTPException

from app.services.event_store import (
    clear_all,
    get_lo2_log_events,
    get_lo2_metric_events,
    get_modsec_events,
    get_summary,
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


@router.post("/clear")
async def clear_events():
    """Clear all event stores."""
    clear_all()
    return {"status": "cleared", "message": "All event stores cleared"}
