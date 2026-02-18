"""Pydantic schemas for request/response validation."""
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"


class ModSecRequest(BaseModel):
    """ModSecurity prediction request."""
    request_text: str = Field(..., description="HTTP request text to analyze")


class ModSecResponse(BaseModel):
    """ModSecurity prediction response."""
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score between 0 and 1")
    threat_type: str = Field(..., description="Detected threat type")
    top_signals: List[str] = Field(default_factory=list, description="Top detected security signals")


class LO2LogRequest(BaseModel):
    """LO2 log anomaly detection request."""
    log_text: str = Field(..., description="Log text to analyze")


class LO2LogResponse(BaseModel):
    """LO2 log anomaly detection response."""
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score between 0 and 1")


class LO2MetricRequest(BaseModel):
    """LO2 metric anomaly detection request."""
    metrics: Dict[str, float] = Field(..., description="Dictionary of metric name-value pairs")


class LO2MetricResponse(BaseModel):
    """LO2 metric anomaly detection response."""
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score between 0 and 1")


class AnalyzeExplainRequest(BaseModel):
    """Request for AI explanation - event_id or raw event data."""
    event_id: Optional[str] = Field(None, description="Event ID from unified store")
    event_data: Optional[Dict] = Field(None, description="Raw event payload for analysis")


class AnalyzeCorrelatedRequest(BaseModel):
    """Request for correlated incident analysis."""
    incident_ts: Optional[float] = Field(None, description="Incident bucket timestamp")
    event_ids: Optional[List[str]] = Field(None, description="Event IDs in incident")
