"""LO2 log and metric anomaly detection router."""
import logging

import numpy as np
from fastapi import APIRouter, HTTPException

from app.schemas import LO2LogRequest, LO2LogResponse, LO2MetricRequest, LO2MetricResponse
from app.services.event_store import add_lo2_log_event, add_lo2_metric_event
from app.services.model_loader import model_loader

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/score", tags=["lo2"])


def normalize_anomaly_score(score: float) -> float:
    """Normalize isolation forest anomaly score to 0-1 range.
    
    Isolation Forest returns:
    - Negative scores: normal (closer to 0 = more normal)
    - Positive scores: anomaly (higher = more anomalous)
    
    We normalize to 0-1 where 1 = most anomalous.
    """
    # Simple sigmoid normalization
    normalized = 1 / (1 + np.exp(-score))
    return float(np.clip(normalized, 0.0, 1.0))


@router.post("/lo2/log", response_model=LO2LogResponse)
async def score_lo2_log(request: LO2LogRequest) -> LO2LogResponse:
    """
    Score log text for anomaly detection.
    
    - **log_text**: Log text to analyze
    - Returns: anomaly_score (0-1, where 1 = most anomalous)
    """
    try:
        # Load models
        tfidf, model = model_loader.get_lo2_log_models()
        
        # Transform text
        X = tfidf.transform([request.log_text])
        
        # Predict anomaly score
        score = model.decision_function(X)[0]
        
        # Normalize to 0-1
        anomaly_score = normalize_anomaly_score(score)
        
        # Store event
        add_lo2_log_event(request.log_text, anomaly_score)
        
        return LO2LogResponse(anomaly_score=anomaly_score)
    
    except FileNotFoundError as e:
        logger.error(f"Model file not found: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Error in LO2 log scoring: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(e)}")


@router.post("/lo2/metric", response_model=LO2MetricResponse)
async def score_lo2_metric(request: LO2MetricRequest) -> LO2MetricResponse:
    """
    Score metrics for anomaly detection.
    
    - **metrics**: Dictionary of metric name-value pairs
    - Returns: anomaly_score (0-1, where 1 = most anomalous)
    
    Note: Only metrics from selected_metric_columns.csv are used.
    Missing metrics are filled with 0, extra metrics are ignored.
    """
    try:
        # Load models and columns
        scaler, model, metric_columns = model_loader.get_lo2_metric_models()
        
        if not metric_columns:
            logger.warning("No metric columns found, using empty feature vector")
            raise HTTPException(
                status_code=500,
                detail="Metric columns configuration not found. Cannot process metrics."
            )
        
        # Build feature vector from request metrics
        feature_vector = []
        for col in metric_columns:
            # Get value from request, default to 0
            value = request.metrics.get(col, 0.0)
            feature_vector.append(float(value))
        
        # Convert to numpy array and reshape for single sample
        X = np.array(feature_vector).reshape(1, -1)
        
        # Scale features
        X_scaled = scaler.transform(X)
        
        # Predict anomaly score
        score = model.decision_function(X_scaled)[0]
        
        # Normalize to 0-1
        anomaly_score = normalize_anomaly_score(score)
        
        # Store event
        add_lo2_metric_event(request.metrics, anomaly_score)
        
        return LO2MetricResponse(anomaly_score=anomaly_score)
    
    except FileNotFoundError as e:
        logger.error(f"Model file not found: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in LO2 metric scoring: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(e)}")
