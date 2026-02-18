"""AI analysis and explainability endpoints (Gemini)."""
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from app.schemas import AnalyzeCorrelatedRequest, AnalyzeExplainRequest
from app.services.event_store import get_correlated_incidents, get_event_by_id
from app.services.gemini_service import (
    analyze_correlated_incident,
    explain_lo2_event,
    explain_modsec_event,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("/explain")
async def explain_event(request: AnalyzeExplainRequest) -> Dict[str, Any]:
    """
    Get AI (Gemini) explanation for a single event.
    Pass event_id or event_data. Returns Türkçe açıklama.
    """
    from app.core.settings import settings
    if not settings.GEMINI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Gemini API key not configured. Set GEMINI_API_KEY environment variable.",
        )

    event: Dict | None = None
    if request.event_id:
        event = get_event_by_id(request.event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event not found: {request.event_id}")
    elif request.event_data:
        # event_data can be full event or payload with type
        ed = request.event_data
        evt_type = ed.get("type", "modsec")
        event = {
            "type": evt_type,
            "payload": ed,
            "combined_score": ed.get("risk_score", ed.get("anomaly_score", 0)),
            "threat_type": ed.get("threat_type"),
            "top_signals": ed.get("top_signals", []),
        }
    else:
        raise HTTPException(status_code=400, detail="Provide event_id or event_data")

    evt_type = event.get("type", "")
    payload = event.get("payload", event)
    explanation = None

    if evt_type == "modsec":
        explanation = explain_modsec_event(
            request_text=payload.get("request_text", ""),
            threat_type=event.get("threat_type", payload.get("threat_type", "OTHER")),
            risk_score=event.get("combined_score", payload.get("risk_score", 0)),
            top_signals=event.get("top_signals", payload.get("top_signals", [])),
        )
    elif evt_type == "lo2_log":
        explanation = explain_lo2_event(
            event_type="lo2_log",
            content=payload.get("log_text", str(payload)),
            anomaly_score=event.get("combined_score", payload.get("anomaly_score", 0)),
        )
    elif evt_type == "lo2_metric":
        content = str(payload.get("metrics_preview", payload))
        explanation = explain_lo2_event(
            event_type="lo2_metric",
            content=content,
            anomaly_score=event.get("combined_score", payload.get("anomaly_score", 0)),
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown event type for explanation: {evt_type}",
        )

    if not explanation:
        raise HTTPException(
            status_code=503,
            detail="Gemini explanation unavailable. Check API key and network.",
        )

    return {"event_id": event.get("event_id"), "explanation": explanation}


@router.post("/correlated")
async def analyze_correlated(request: AnalyzeCorrelatedRequest) -> Dict[str, Any]:
    """
    Get AI (Gemini) correlation analysis for a correlated incident.
    Pass incident_ts or event_ids to identify the incident.
    """
    from app.core.settings import settings
    if not settings.GEMINI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Gemini API key not configured. Set GEMINI_API_KEY environment variable.",
        )

    incidents = get_correlated_incidents(limit=100)
    target_events: List[Dict] = []

    if request.event_ids:
        for inc in incidents:
            if set(request.event_ids) & set(inc.get("event_ids", [])):
                target_events = inc.get("events", [])
                break
    elif request.incident_ts is not None:
        for inc in incidents:
            if inc.get("ts") == request.incident_ts:
                target_events = inc.get("events", [])
                break

    if not target_events:
        # Use most recent incident if no specific request
        if incidents:
            target_events = incidents[0].get("events", [])
        else:
            raise HTTPException(
                status_code=404,
                detail="No correlated incident found. Run ModSec and LO2 replays to generate data.",
            )

    analysis = analyze_correlated_incident(target_events)
    if not analysis:
        raise HTTPException(
            status_code=503,
            detail="Gemini analysis unavailable. Check API key and network.",
        )

    return {
        "events_count": len(target_events),
        "analysis": analysis,
    }


