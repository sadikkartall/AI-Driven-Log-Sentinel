"""In-memory event store for demo purposes (thread-safe).

Supports both legacy separate stores and unified/correlated event view.
"""
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional

# Thread-safe locks
_modsec_lock = threading.Lock()
_lo2_log_lock = threading.Lock()
_lo2_metric_lock = threading.Lock()
_unified_lock = threading.Lock()

# Time window for correlation (seconds) - events within this window are considered correlated
CORRELATION_WINDOW_SEC = 60

# In-memory event stores (max 500 events each) - legacy, kept for backward compat
modsec_events: Deque[Dict] = deque(maxlen=500)
lo2_log_events: Deque[Dict] = deque(maxlen=500)
lo2_metric_events: Deque[Dict] = deque(maxlen=500)

# Unified event store: merged timeline with event type discriminator (max 1000)
# Each: {ts, type, event_id, payload, combined_score}
unified_events: Deque[Dict] = deque(maxlen=1000)

_event_id_counter = 0


def _next_id() -> str:
    """Generate unique event ID."""
    global _event_id_counter
    with _unified_lock:
        _event_id_counter += 1
        return f"evt_{int(time.time() * 1000)}_{_event_id_counter}"


def add_modsec_event(
    request_text: str, risk_score: float, threat_type: str, top_signals: List[str]
) -> str:
    """Add ModSecurity event to store (thread-safe). Returns event_id."""
    ts = time.time()
    event_id = _next_id()
    payload = {
        "request_text": request_text[:200],
        "risk_score": risk_score,
        "threat_type": threat_type,
        "top_signals": top_signals,
    }

    with _modsec_lock:
        modsec_events.append({
            "ts": ts,
            "event_id": event_id,
            "request_text": request_text[:200],
            "risk_score": risk_score,
            "threat_type": threat_type,
            "top_signals": top_signals,
            "timestamp": ts,
        })

    with _unified_lock:
        unified_events.append({
            "ts": ts,
            "event_id": event_id,
            "type": "modsec",
            "payload": payload,
            "combined_score": risk_score,
            "threat_type": threat_type,
            "top_signals": top_signals,
        })

    return event_id


def add_lo2_log_event(log_text: str, anomaly_score: float) -> str:
    """Add LO2 log event to store (thread-safe). Returns event_id."""
    ts = time.time()
    event_id = _next_id()
    payload = {"log_text": log_text[:200], "anomaly_score": anomaly_score}

    with _lo2_log_lock:
        lo2_log_events.append({
            "ts": ts,
            "event_id": event_id,
            "log_text": log_text[:200],
            "anomaly_score": anomaly_score,
            "timestamp": ts,
        })

    with _unified_lock:
        unified_events.append({
            "ts": ts,
            "event_id": event_id,
            "type": "lo2_log",
            "payload": payload,
            "combined_score": anomaly_score,
        })

    return event_id


def add_lo2_metric_event(metrics: Dict, anomaly_score: float) -> str:
    """Add LO2 metric event to store (thread-safe). Returns event_id."""
    ts = time.time()
    event_id = _next_id()
    metrics_preview = {k: v for k, v in list(metrics.items())[:5]}

    with _lo2_metric_lock:
        lo2_metric_events.append({
            "ts": ts,
            "event_id": event_id,
            "metrics_preview": metrics_preview,
            "metrics_count": len(metrics),
            "anomaly_score": anomaly_score,
            "timestamp": ts,
        })

    with _unified_lock:
        unified_events.append({
            "ts": ts,
            "event_id": event_id,
            "type": "lo2_metric",
            "payload": {
                "metrics_preview": metrics_preview,
                "metrics_count": len(metrics),
                "anomaly_score": anomaly_score,
            },
            "combined_score": anomaly_score,
        })

    return event_id


def get_modsec_events(limit: int = 500) -> List[Dict]:
    """Get ModSecurity events (thread-safe)."""
    with _modsec_lock:
        return list(modsec_events)[-limit:]


def get_lo2_log_events(limit: int = 500) -> List[Dict]:
    """Get LO2 log events (thread-safe)."""
    with _lo2_log_lock:
        return list(lo2_log_events)[-limit:]


def get_lo2_metric_events(limit: int = 500) -> List[Dict]:
    """Get LO2 metric events (thread-safe)."""
    with _lo2_metric_lock:
        return list(lo2_metric_events)[-limit:]


def get_unified_events(limit: int = 500) -> List[Dict]:
    """Get unified event timeline (all types merged, sorted by timestamp, newest first)."""
    with _unified_lock:
        events = list(unified_events)[-limit:]
    return sorted(events, key=lambda x: x["ts"], reverse=True)


def get_correlated_incidents(limit: int = 50) -> List[Dict]:
    """
    Get incidents where ModSec and LO2 events occur in the same time window.
    Uses 60-second buckets: events in same bucket with both types = correlated.
    """
    with _unified_lock:
        events = list(unified_events)

    if not events:
        return []

    # Group by time bucket (60s)
    buckets: Dict[int, List[Dict]] = {}
    for evt in events:
        bucket = int(evt["ts"] // CORRELATION_WINDOW_SEC) * CORRELATION_WINDOW_SEC
        if bucket not in buckets:
            buckets[bucket] = []
        buckets[bucket].append(evt)

    incidents: List[Dict] = []
    for bucket_ts, window_events in sorted(buckets.items(), reverse=True):
        types_in_window = {e["type"] for e in window_events}
        has_modsec = "modsec" in types_in_window
        has_lo2 = "lo2_log" in types_in_window or "lo2_metric" in types_in_window

        if has_modsec and has_lo2:
            scores = [e["combined_score"] for e in window_events]
            combined_score = sum(scores) / len(scores)
            max_score = max(scores)
            if max_score > 0.7:
                combined_score = min(1.0, combined_score * 1.2)

            incidents.append({
                "ts": bucket_ts,
                "event_ids": [e["event_id"] for e in window_events],
                "events": window_events,
                "combined_score": round(combined_score, 4),
                "has_modsec": True,
                "has_lo2": True,
                "severity": (
                    "critical" if combined_score > 0.7
                    else "high" if combined_score > 0.5
                    else "medium"
                ),
            })

    return incidents[:limit]


def get_event_by_id(event_id: str) -> Optional[Dict]:
    """Get single event by ID from unified store."""
    with _unified_lock:
        for evt in unified_events:
            if evt.get("event_id") == event_id:
                return dict(evt)
    return None


def get_summary() -> Dict:
    """Get event counts summary (thread-safe)."""
    with _modsec_lock:
        modsec_count = len(modsec_events)
    with _lo2_log_lock:
        lo2_log_count = len(lo2_log_events)
    with _lo2_metric_lock:
        lo2_metric_count = len(lo2_metric_events)
    with _unified_lock:
        unified_count = len(unified_events)

    return {
        "modsec": modsec_count,
        "lo2_log": lo2_log_count,
        "lo2_metric": lo2_metric_count,
        "unified_total": unified_count,
        "correlated_count": len(get_correlated_incidents(limit=1000)),
    }


def clear_all() -> None:
    """Clear all event stores (thread-safe)."""
    with _modsec_lock:
        modsec_events.clear()
    with _lo2_log_lock:
        lo2_log_events.clear()
    with _lo2_metric_lock:
        lo2_metric_events.clear()
    with _unified_lock:
        unified_events.clear()
