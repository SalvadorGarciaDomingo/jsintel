from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    PROJECT_NAME: str = "Vysion OSINT API"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security & CORS
    BACKEND_CORS_ORIGINS: list = [
        "http://localhost:8000",
        "https://sjintel.com",
        "https://www.sjintel.com",
        "http://localhost:5500", # Dev Local Frontend
        "http://127.0.0.1:5500"
    ]

    # External APIs
    GITHUB_TOKEN: str = ""
    DEEPWEB_API_KEY: str = ""
    DEEPWEB_API_URL: str = "https://academic-deepweb-api.example.com/v1"
    
    # AI Configuration
    AI_PROVIDER: str = "mock" # options: "openai", "anthropic", "mock"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    
    # Deployment
    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
