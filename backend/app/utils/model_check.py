"""Utility to check model files."""
import pickle
from pathlib import Path


def check_model_file(model_path: Path) -> dict:
    """Check if a model file is valid."""
    result = {
        "exists": False,
        "size": 0,
        "valid": False,
        "error": None,
        "type": None
    }
    
    if not model_path.exists():
        result["error"] = f"File does not exist: {model_path}"
        return result
    
    result["exists"] = True
    result["size"] = model_path.stat().st_size
    
    if result["size"] == 0:
        result["error"] = "File is empty"
        return result
    
    # Try to load the pickle file
    try:
        with open(model_path, "rb") as f:
            obj = pickle.load(f)
        result["valid"] = True
        result["type"] = str(type(obj))
    except Exception as e:
        result["error"] = str(e)
    
    return result
