"""Gemini API service for explainable AI and correlation analysis."""
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_GEMINI_CLIENT = None


def _get_client():
    """Lazy-load Gemini client."""
    global _GEMINI_CLIENT
    if _GEMINI_CLIENT is not None:
        return _GEMINI_CLIENT
    try:
        import google.generativeai as genai
        from app.core.settings import settings
        if not settings.GEMINI_API_KEY:
            return None
        genai.configure(api_key=settings.GEMINI_API_KEY)
        _GEMINI_CLIENT = genai.GenerativeModel("gemini-1.5-flash")
        return _GEMINI_CLIENT
    except ImportError:
        logger.warning("google-generativeai not installed. Run: pip install google-generativeai")
        return None
    except Exception as e:
        logger.warning(f"Gemini client init failed: {e}")
        return None


def explain_modsec_event(
    request_text: str,
    threat_type: str,
    risk_score: float,
    top_signals: List[str],
) -> Optional[str]:
    """
    Generate human-readable explanation for ModSec threat classification.
    """
    model = _get_client()
    if not model:
        return None

    prompt = f"""Sen bir güvenlik analisti asistansın. Aşağıdaki HTTP isteği ModSecurity modeli tarafından analiz edildi.
Sonuç: Tehdit tipi={threat_type}, Risk skoru={risk_score:.2f}.
Tespit edilen sinyaller: {', '.join(top_signals[:5]) if top_signals else 'yok'}.

İstek metni: {request_text[:500]}

Kısa ve anlaşılır Türkçe açıklama yaz (2-4 cümle):
1) Bu istek neden bu tehdit tipi olarak sınıflandırıldı?
2) Hangi öğeler şüpheli?
3) Önerilen aksiyon nedir?"""

    try:
        response = model.generate_content(prompt)
        return response.text.strip() if response and response.text else None
    except Exception as e:
        logger.error(f"Gemini explain_modsec error: {e}")
        return None


def explain_lo2_event(
    event_type: str,
    content: str,
    anomaly_score: float,
) -> Optional[str]:
    """
    Generate human-readable explanation for LO2 anomaly.
    event_type: 'lo2_log' or 'lo2_metric'
    content: log text or metrics summary
    """
    model = _get_client()
    if not model:
        return None

    type_label = "log" if event_type == "lo2_log" else "metrik"
    prompt = f"""Sen bir güvenlik analisti asistansın. Aşağıdaki {type_label} verisi anomali tespit modeli tarafından analiz edildi.
Anomali skoru: {anomaly_score:.2f} (1'e yakın = daha anormal).

Veri: {content[:600]}

Kısa ve anlaşılır Türkçe açıklama yaz (2-3 cümle):
1) Bu veri neden anormal görünüyor?
2) Olası sebep/senaryo nedir?
3) İnceleme önerisi."""

    try:
        response = model.generate_content(prompt)
        return response.text.strip() if response and response.text else None
    except Exception as e:
        logger.error(f"Gemini explain_lo2 error: {e}")
        return None


def analyze_correlated_incident(events: List[Dict]) -> Optional[str]:
    """
    Analyze a correlated incident (ModSec + LO2 events in same time window).
    Returns Gemini's correlation analysis in Turkish.
    """
    model = _get_client()
    if not model:
        return None

    events_summary = []
    for evt in events[:10]:  # Max 10 events
        evt_type = evt.get("type", "unknown")
        ts = evt.get("ts", 0)
        payload = evt.get("payload", evt)
        score = evt.get("combined_score", 0)
        line = f"- [{evt_type}] skor={score:.2f}, ts={ts}"
        if evt_type == "modsec":
            line += f", tehdit={payload.get('threat_type', '')}"
            line += f", sinyaller={payload.get('top_signals', [])[:3]}"
        elif evt_type == "lo2_log":
            line += f", log={str(payload.get('log_text', ''))[:80]}..."
        elif evt_type == "lo2_metric":
            line += f", metrik_sayısı={payload.get('metrics_count', 0)}"
        events_summary.append(line)

    prompt = f"""Sen bir SIEM güvenlik analisti asistansın. Aynı zaman penceresinde hem ModSecurity tehdit tespiti hem LO2 log/metrik anomali tespiti tetiklenmiş olaylar var.
Bu korelasyonu analiz et.

Olaylar:
{chr(10).join(events_summary)}

Kısa ve profesyonel Türkçe analiz yaz (3-5 cümle):
1) Olaylar arasındaki olası ilişki nedir? (HTTP tehdidi -> log/metrik anomalisi zinciri var mı?)
2) Saldırı senaryosu tahmini
3) Önerilen öncelik ve aksiyonlar"""

    try:
        response = model.generate_content(prompt)
        return response.text.strip() if response and response.text else None
    except Exception as e:
        logger.error(f"Gemini analyze_correlated error: {e}")
        return None
