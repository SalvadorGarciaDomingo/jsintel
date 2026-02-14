from pydantic_settings import BaseSettings
from typing import List, Optional
from functools import lru_cache

class Settings(BaseSettings):
    PROJECT_NAME: str = "SJ INTEL OSINT API"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "production"
    
    # CORS (Strict as requested)
    BACKEND_CORS_ORIGINS: List[str] = [
        "https://sjintel.com",
        "https://www.sjintel.com"
    ]

    # Security
    SECRET_KEY: str = "changeme_in_production"
    
    # --- REAL API KEYS (Must be set in Render Env Vars) ---
    
    # IA
    GOOGLE_API_KEY: str # Required
    AI_MODEL: str = "gemini-2.0-flash"
    
    # OSINT Services
    VYSION_API_KEY: str # Required
    VIRUSTOTAL_API_KEY: str # Required
    HIBP_API_KEY: str # Required
    URLSCAN_API_KEY: str # Required
    ABUSEIPDB_API_KEY: str # Required
    
    # Recommended / Optional (Defaults to empty string if not set, but better to force them if critical)
    # Keeping them optional to avoid crash if user forgets purely optional ones, 
    # but the core ones above are marked required (no default value)
    SHODAN_API_KEY: Optional[str] = ""
    HUNTER_API_KEY: Optional[str] = ""
    GITHUB_TOKEN: Optional[str] = ""
    
    # Discord
    DISCORD_BOT_TOKEN: Optional[str] = ""

    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings():
    return Settings()
