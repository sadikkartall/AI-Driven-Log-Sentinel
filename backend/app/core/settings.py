"""Application settings and configuration."""
import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    # Model paths
    MODSEC_MODEL_DIR: Path = Path("outputs/models/modsec")
    LO2_MODEL_DIR: Path = Path("outputs/models/lo2")
    LO2_REPORTS_DIR: Path = Path("outputs/reports/lo2")
    
    # CORS settings
    CORS_ORIGINS: List[str] = ["*"]
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    # Gemini API (optional - for explainable AI / correlation analysis)
    GEMINI_API_KEY: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
