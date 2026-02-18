"""Model loading service with lazy loading and caching."""
import logging
import pickle
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np
from sklearn.base import BaseEstimator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from app.core.settings import settings

logger = logging.getLogger(__name__)


class ModelLoader:
    """Service for loading and caching ML models."""
    
    def __init__(self):
        self._modsec_model: Optional[BaseEstimator] = None
        self._lo2_log_tfidf: Optional[TfidfVectorizer] = None
        self._lo2_log_model: Optional[BaseEstimator] = None
        self._lo2_metric_scaler: Optional[StandardScaler] = None
        self._lo2_metric_model: Optional[BaseEstimator] = None
        self._lo2_metric_columns: Optional[list] = None
    
    def _resolve_path(self, path: Path) -> Path:
        """Resolve relative paths to absolute paths."""
        if path.is_absolute():
            return path
        
        # List of possible base directories to try
        base_dirs = [
            Path.cwd(),  # Current working directory
            Path("/app"),  # Docker container root
            Path("/app/backend"),  # Docker backend directory
            Path(__file__).parent.parent.parent,  # Backend directory (local)
            Path(__file__).parent.parent,  # App directory
        ]
        
        for base_dir in base_dirs:
            test_path = base_dir / path
            if test_path.exists():
                logger.debug(f"Resolved {path} to {test_path}")
                return test_path
        
        # Return original path if none found (will fail later with better error)
        logger.warning(f"Could not resolve path {path}, using as-is")
        return path
    
    def _find_modsec_model(self) -> Path:
        """Find the best available ModSecurity model file."""
        model_dir = self._resolve_path(settings.MODSEC_MODEL_DIR)
        if not model_dir.exists():
            raise FileNotFoundError(
                f"ModSecurity model directory not found: {model_dir.absolute()}. "
                f"Searched in: {Path.cwd()}, {Path(__file__).parent.parent.parent}"
            )
        
        # Priority order: stable > balanced > default
        for model_name in ["threat_model_stable.pkl", "threat_model_balanced.pkl", "threat_model.pkl"]:
            model_path = model_dir / model_name
            if model_path.exists():
                logger.info(f"Using ModSecurity model: {model_path}")
                return model_path
        
        raise FileNotFoundError(
            f"No ModSecurity model found in {model_dir.absolute()}. "
            f"Expected one of: threat_model_stable.pkl, threat_model_balanced.pkl, threat_model.pkl"
        )
    
    def _load_lo2_metric_columns(self) -> list:
        """Load selected metric columns from CSV file."""
        reports_dir = self._resolve_path(settings.LO2_REPORTS_DIR)
        csv_path = reports_dir / "selected_metric_columns.csv"
        if not csv_path.exists():
            logger.warning(
                f"selected_metric_columns.csv not found at {csv_path.absolute()}. "
                f"Using empty column list."
            )
            return []
        
        import pandas as pd
        df = pd.read_csv(csv_path)
        # First column is header, get the actual column names
        columns = df.iloc[:, 0].tolist()
        # Remove header if present
        if columns and columns[0] == "selected_metric_cols":
            columns = columns[1:]
        logger.info(f"Loaded {len(columns)} metric columns from {csv_path}")
        return columns
    
    def get_modsec_model(self) -> BaseEstimator:
        """Get ModSecurity model (lazy load with cache)."""
        if self._modsec_model is None:
            model_dir = self._resolve_path(settings.MODSEC_MODEL_DIR)
            if not model_dir.exists():
                raise FileNotFoundError(
                    f"ModSecurity model directory not found: {model_dir.absolute()}"
                )
            
            # Try all available models in priority order
            model_priority = ["threat_model_stable.pkl", "threat_model_balanced.pkl", "threat_model.pkl"]
            last_error = None
            
            for model_name in model_priority:
                model_path = model_dir / model_name
                if not model_path.exists():
                    logger.debug(f"Model file not found: {model_path}")
                    continue
                
                try:
                    logger.info(f"Attempting to load: {model_path}")
                    self._load_single_model(model_path)
                    logger.info(f"Successfully loaded model: {model_path}")
                    break
                except Exception as e:
                    last_error = e
                    logger.warning(f"Failed to load {model_path}: {e}")
                    self._modsec_model = None  # Reset on failure
                    continue
            else:
                # All models failed
                raise ValueError(
                    f"Failed to load any ModSecurity model from {model_dir}. "
                    f"Tried: {model_priority}. "
                    f"Last error: {last_error}"
                )
        
        return self._modsec_model
    
    def _load_single_model(self, model_path: Path) -> None:
        """Load a single model file with multiple strategies."""
        # Check file size
        file_size = model_path.stat().st_size
        if file_size == 0:
            raise ValueError(f"Model file is empty: {model_path}")
        if file_size < 100:
            logger.warning(f"Model file is very small ({file_size} bytes), might be corrupted")
        
        try:
            # Strategy 1: Try joblib first (scikit-learn models are usually saved with joblib)
            # Suppress version warnings for now
            import warnings
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
                try:
                    logger.debug("Trying joblib.load")
                    model = joblib.load(model_path)
                    if hasattr(model, 'predict'):
                        self._modsec_model = model
                        logger.info(f"ModSecurity model loaded successfully with joblib. Type: {type(model)}")
                        return
                    else:
                        raise ValueError(f"Loaded object does not have 'predict' method. Type: {type(model)}")
                except Exception as joblib_error:
                    logger.debug(f"joblib.load failed: {joblib_error}")
                    last_error = joblib_error
            
            # Strategy 2-4: Try pickle with different encodings
            with open(model_path, "rb") as f:
                file_content = f.read()
            
            if len(file_content) < 2:
                raise ValueError("File is too small to be a valid pickle file")
            
            pickle_strategies = [
                ("pickle_standard", lambda: pickle.loads(file_content)),
                ("pickle_latin1", lambda: pickle.loads(file_content, encoding='latin1')),
                ("pickle_bytes", lambda: pickle.loads(file_content, encoding='bytes')),
            ]
            
            for strategy_name, strategy_func in pickle_strategies:
                try:
                    logger.debug(f"Trying loading strategy: {strategy_name}")
                    model = strategy_func()
                    
                    # Verify model has required methods
                    if not hasattr(model, 'predict'):
                        raise ValueError(f"Loaded object does not have 'predict' method. Type: {type(model)}")
                    
                    self._modsec_model = model
                    logger.info(f"ModSecurity model loaded successfully with strategy '{strategy_name}'. Type: {type(model)}")
                    return
                except Exception as e:
                    last_error = e
                    logger.debug(f"Strategy '{strategy_name}' failed: {e}")
                    continue
            
            # All strategies failed
            first_bytes_hex = file_content[:50].hex() if len(file_content) >= 50 else file_content.hex()
            raise ValueError(
                f"All pickle loading strategies failed for {model_path}. "
                f"Last error: {last_error}. "
                f"File size: {file_size} bytes. "
                f"First 50 bytes (hex): {first_bytes_hex}. "
                f"The file might be corrupted, incomplete, or saved with unsupported pickle protocol."
            )
            
        except pickle.UnpicklingError as e:
            # Try to get more info about the file
            try:
                with open(model_path, "rb") as f:
                    first_bytes = f.read(50)
                first_bytes_hex = first_bytes.hex()
            except:
                first_bytes_hex = "could not read"
            
            raise ValueError(
                f"Failed to unpickle model file {model_path}. "
                f"Error: {e}. "
                f"File size: {file_size} bytes. "
                f"First 50 bytes (hex): {first_bytes_hex}. "
                f"The file might be corrupted, incomplete, or saved with incompatible pickle protocol."
            )
        except Exception as e:
            raise ValueError(
                f"Failed to load model from {model_path}. "
                f"Error: {str(e)}. "
                f"File exists: {model_path.exists()}, Size: {file_size} bytes"
            )
    
    def get_lo2_log_models(self) -> Tuple[TfidfVectorizer, BaseEstimator]:
        """Get LO2 log models (lazy load with cache)."""
        if self._lo2_log_tfidf is None or self._lo2_log_model is None:
            model_dir = self._resolve_path(settings.LO2_MODEL_DIR)
            
            tfidf_path = model_dir / "log_tfidf.pkl"
            model_path = model_dir / "log_isoforest.pkl"
            
            if not tfidf_path.exists():
                raise FileNotFoundError(
                    f"LO2 log TF-IDF model not found: {tfidf_path.absolute()}"
                )
            if not model_path.exists():
                raise FileNotFoundError(
                    f"LO2 log isolation forest model not found: {model_path.absolute()}"
                )
            
            logger.info(f"Loading LO2 log models from {model_dir}")
            try:
                # Try joblib first, then pickle (suppress version warnings)
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning)
                    warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
                    try:
                        self._lo2_log_tfidf = joblib.load(tfidf_path)
                        self._lo2_log_model = joblib.load(model_path)
                        logger.info("LO2 log models loaded successfully with joblib")
                    except Exception:
                        # Fallback to pickle
                        with open(tfidf_path, "rb") as f:
                            self._lo2_log_tfidf = pickle.load(f)
                        with open(model_path, "rb") as f:
                            self._lo2_log_model = pickle.load(f)
                        logger.info("LO2 log models loaded successfully with pickle")
            except Exception as e:
                raise ValueError(
                    f"Failed to load LO2 log models. "
                    f"Files might be corrupted. Error: {e}"
                )
        
        return self._lo2_log_tfidf, self._lo2_log_model
    
    def get_lo2_metric_models(self) -> Tuple[StandardScaler, BaseEstimator, list]:
        """Get LO2 metric models (lazy load with cache)."""
        if self._lo2_metric_scaler is None or self._lo2_metric_model is None:
            model_dir = self._resolve_path(settings.LO2_MODEL_DIR)
            
            scaler_path = model_dir / "metric_scaler.pkl"
            model_path = model_dir / "metric_isoforest.pkl"
            
            if not scaler_path.exists():
                raise FileNotFoundError(
                    f"LO2 metric scaler not found: {scaler_path.absolute()}"
                )
            if not model_path.exists():
                raise FileNotFoundError(
                    f"LO2 metric isolation forest model not found: {model_path.absolute()}"
                )
            
            logger.info(f"Loading LO2 metric models from {model_dir}")
            try:
                # Try joblib first, then pickle (suppress version warnings)
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning)
                    warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
                    try:
                        self._lo2_metric_scaler = joblib.load(scaler_path)
                        self._lo2_metric_model = joblib.load(model_path)
                        logger.info("LO2 metric models loaded successfully with joblib")
                    except Exception:
                        # Fallback to pickle
                        with open(scaler_path, "rb") as f:
                            self._lo2_metric_scaler = pickle.load(f)
                        with open(model_path, "rb") as f:
                            self._lo2_metric_model = pickle.load(f)
                        logger.info("LO2 metric models loaded successfully with pickle")
            except Exception as e:
                raise ValueError(
                    f"Failed to load LO2 metric models. "
                    f"Files might be corrupted. Error: {e}"
                )
        
        # Load metric columns if not already loaded
        if self._lo2_metric_columns is None:
            self._lo2_metric_columns = self._load_lo2_metric_columns()
        
        return self._lo2_metric_scaler, self._lo2_metric_model, self._lo2_metric_columns


# Global singleton instance
model_loader = ModelLoader()
