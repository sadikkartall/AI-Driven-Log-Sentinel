"""ModSecurity threat detection router."""
import logging
import re
from typing import List

import numpy as np
from fastapi import APIRouter, HTTPException
from sklearn.base import BaseEstimator

from app.schemas import ModSecRequest, ModSecResponse
from app.services.event_store import add_modsec_event
from app.services.model_loader import model_loader

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/predict", tags=["modsec"])

# Threat type mapping (adjust based on your model's classes)
THREAT_TYPES = ["SQLI", "XSS", "RCE", "TRAVERSAL", "SCAN", "OTHER"]

# Security signal patterns
SIGNAL_PATTERNS = {
    "SQLI": [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from)",
        r"(?i)(or\s+1\s*=\s*1|'or'|'and'|--|;|/\*|\*/)",
        r"(?i)(exec\s*\(|sp_executesql|xp_cmdshell)",
    ],
    "XSS": [
        r"(?i)(<script|javascript:|onerror=|onload=|onclick=|alert\s*\()",
        r"(?i)(<iframe|<img|<svg|<body)",
        r"(?i)(document\.cookie|window\.location|eval\s*\()",
    ],
    "RCE": [
        r"(?i)(cmd\s*=|powershell|bash|sh\s+-c|exec\s+|system\s*\()",
        r"(?i)(/bin/sh|/bin/bash|/usr/bin/python|perl\s+-e)",
        r"(?i)(eval\s*\(|base64_decode|shell_exec)",
    ],
    "TRAVERSAL": [
        r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c)",
        r"(?i)(etc/passwd|etc/shadow|windows/system32|boot\.ini)",
        r"(?i)(\.\./\.\./\.\./|%2e%2e%2f)",
    ],
    "SCAN": [
        r"(?i)(nikto|nmap|gobuster|dirb|sqlmap|burp)",
        r"(?i)(user-agent.*scanner|user-agent.*bot)",
        r"(?i)(\.git/|\.env|\.DS_Store|wp-admin|phpmyadmin)",
    ],
}


def extract_top_signals(request_text: str, limit: int = 5) -> List[str]:
    """Extract top security signals from request text."""
    signals = []
    
    for threat_type, patterns in SIGNAL_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, request_text)
            if matches:
                # Get unique matches, limit length
                for match in set(matches):
                    if len(match) > 3:  # Filter very short matches
                        signals.append(f"{threat_type}: {match[:50]}")
                        if len(signals) >= limit:
                            return signals[:limit]
    
    return signals[:limit]


def normalize_score(score: float, model: BaseEstimator) -> float:
    """Normalize model output to 0-1 range."""
    # If model has predict_proba, use max probability
    if hasattr(model, "predict_proba"):
        return float(np.max(score))
    
    # If model has decision_function, normalize it
    if hasattr(model, "decision_function"):
        # Isolation Forest typically returns negative scores for anomalies
        # Normalize to 0-1: score -> sigmoid or min-max normalization
        score_val = float(score[0]) if isinstance(score, np.ndarray) else float(score)
        # Simple normalization: assume scores are in reasonable range
        # For IF: negative = anomaly, positive = normal
        # Convert to 0-1: use sigmoid or min-max
        normalized = 1 / (1 + np.exp(-score_val))  # Sigmoid
        return float(np.clip(normalized, 0.0, 1.0))
    
    # Fallback: assume score is already normalized
    return float(np.clip(score, 0.0, 1.0))


@router.post("/modsec", response_model=ModSecResponse)
async def predict_modsec(request: ModSecRequest) -> ModSecResponse:
    """
    Predict threat type and risk score for HTTP request.
    
    - **request_text**: HTTP request text to analyze
    - Returns: risk_score (0-1), threat_type, and top_signals
    """
    try:
        # Load model
        model = model_loader.get_modsec_model()
        
        # Predict
        prediction = model.predict([request.request_text])
        threat_type = prediction[0] if isinstance(prediction, np.ndarray) else str(prediction)
        
        # Get probability/score
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba([request.request_text])[0]
            risk_score = float(np.max(proba))
            # Get predicted class index
            predicted_idx = np.argmax(proba)
            if isinstance(model.classes_, np.ndarray) and len(model.classes_) > predicted_idx:
                threat_type = str(model.classes_[predicted_idx])
        elif hasattr(model, "decision_function"):
            score = model.decision_function([request.request_text])
            risk_score = normalize_score(score, model)
        else:
            # Fallback: use prediction confidence or default
            risk_score = 0.5
        
        # Ensure threat_type is valid
        if threat_type not in THREAT_TYPES:
            # Try to map or default to OTHER
            threat_type_upper = str(threat_type).upper()
            if any(t in threat_type_upper for t in ["SQL", "INJECTION"]):
                threat_type = "SQLI"
            elif any(t in threat_type_upper for t in ["XSS", "SCRIPT"]):
                threat_type = "XSS"
            elif any(t in threat_type_upper for t in ["RCE", "COMMAND", "EXEC"]):
                threat_type = "RCE"
            elif any(t in threat_type_upper for t in ["TRAVERSAL", "PATH"]):
                threat_type = "TRAVERSAL"
            elif any(t in threat_type_upper for t in ["SCAN", "SCANNER"]):
                threat_type = "SCAN"
            else:
                threat_type = "OTHER"
        
        # Extract signals
        top_signals = extract_top_signals(request.request_text)
        
        # Store event
        add_modsec_event(request.request_text, risk_score, threat_type, top_signals)
        
        return ModSecResponse(
            risk_score=risk_score,
            threat_type=threat_type,
            top_signals=top_signals
        )
    
    except FileNotFoundError as e:
        logger.error(f"Model file not found: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Model file not found: {str(e)}. Please check that model files exist in outputs/models/modsec/"
        )
    except ValueError as e:
        logger.error(f"Model loading error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Model loading error: {str(e)}. The model file might be corrupted or incompatible."
        )
    except Exception as e:
        logger.error(f"Error in ModSecurity prediction: {e}", exc_info=True)
        error_msg = str(e)
        if "invalid load key" in error_msg.lower() or "unpickling" in error_msg.lower():
            raise HTTPException(
                status_code=500,
                detail=f"Model file corruption detected: {error_msg}. Please check the model files in outputs/models/modsec/"
            )
        raise HTTPException(status_code=500, detail=f"Prediction error: {error_msg}")
