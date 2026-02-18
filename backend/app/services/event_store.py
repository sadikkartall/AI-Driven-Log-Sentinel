"""In-memory event store for demo purposes (thread-safe)."""
import threading
import time
from collections import deque
from typing import Deque, Dict, List

# Thread-safe locks
_modsec_lock = threading.Lock()
_lo2_log_lock = threading.Lock()
_lo2_metric_lock = threading.Lock()

# In-memory event stores (max 500 events each)
modsec_events: Deque[Dict] = deque(maxlen=500)
lo2_log_events: Deque[Dict] = deque(maxlen=500)
lo2_metric_events: Deque[Dict] = deque(maxlen=500)


def add_modsec_event(request_text: str, risk_score: float, threat_type: str, top_signals: List[str]) -> None:
    """Add ModSecurity event to store (thread-safe)."""
    with _modsec_lock:
        modsec_events.append({
            "ts": time.time(),
            "request_text": request_text[:200],  # Truncate
            "risk_score": risk_score,
            "threat_type": threat_type,
            "top_signals": top_signals,
            "timestamp": time.time()  # Keep for backward compatibility
        })


def add_lo2_log_event(log_text: str, anomaly_score: float) -> None:
    """Add LO2 log event to store (thread-safe)."""
    with _lo2_log_lock:
        lo2_log_events.append({
            "ts": time.time(),
            "log_text": log_text[:200],  # Truncate
            "anomaly_score": anomaly_score,
            "timestamp": time.time()  # Keep for backward compatibility
        })


def add_lo2_metric_event(metrics: Dict, anomaly_score: float) -> None:
    """Add LO2 metric event to store (thread-safe)."""
    with _lo2_metric_lock:
        # Create preview of metrics (first 5 keys)
        metrics_preview = {k: v for k, v in list(metrics.items())[:5]}
        lo2_metric_events.append({
            "ts": time.time(),
            "metrics_preview": metrics_preview,
            "metrics_count": len(metrics),
            "anomaly_score": anomaly_score,
            "timestamp": time.time()  # Keep for backward compatibility
        })


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


def get_summary() -> Dict[str, int]:
    """Get event counts summary (thread-safe)."""
    with _modsec_lock:
        modsec_count = len(modsec_events)
    with _lo2_log_lock:
        lo2_log_count = len(lo2_log_events)
    with _lo2_metric_lock:
        lo2_metric_count = len(lo2_metric_events)
    
    return {
        "modsec": modsec_count,
        "lo2_log": lo2_log_count,
        "lo2_metric": lo2_metric_count
    }


def clear_all() -> None:
    """Clear all event stores (thread-safe)."""
    with _modsec_lock:
        modsec_events.clear()
    with _lo2_log_lock:
        lo2_log_events.clear()
    with _lo2_metric_lock:
        lo2_metric_events.clear()
