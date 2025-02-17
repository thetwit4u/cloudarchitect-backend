from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "AWS Infrastructure Analysis Tool"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str
    
    # JWT Settings
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS Settings
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:3000"]  # Frontend URL
    
    class Config:
        case_sensitive = True
        env_file = ".env"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
