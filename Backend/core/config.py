import os
from typing import Set
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# Ensure dotenv is loaded so BaseSettings picks up variables correctly
load_dotenv()

class Settings(BaseSettings):
    # App Settings
    PORT: int = 8000
    FRONTEND_URL: str = "http://localhost:5173"
    
    # MongoDB Configuration
    MONGO_URI: str = ""
    DATABASE_NAME: str = "Phishing"

    # Security Config
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Rate Limiting Config
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 300
    AUTH_LOGIN_MAX_ATTEMPTS: int = 10
    AUTH_REGISTER_MAX_ATTEMPTS: int = 5
    AUTH_OTP_REQUEST_MAX_ATTEMPTS: int = 5
    AUTH_OTP_VERIFY_MAX_ATTEMPTS: int = 10

    # Email OTP Configuration
    REQUIRE_EMAIL_VERIFICATION: bool = False
    OTP_TTL_MINUTES: int = 10
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_ATTEMPTS: int = 5
    OTP_EMAIL_SENDING_DISABLED: bool = False

    # Brevo API Configuration
    BREVO_API_KEY: str | None = None
    BREVO_API_URL: str = "https://api.brevo.com/v3/smtp/email"

    # SMTP Configuration
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM: str | None = None
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    SMTP_SSL_PORT: int = 465
    SMTP_TIMEOUT_SECONDS: int = 30
    SMTP_FALLBACK_TO_SSL: bool = True

    # Scan File Limits
    MAX_DOCUMENT_UPLOAD_BYTES: int = 10 * 1024 * 1024
    MAX_EMAIL_UPLOAD_BYTES: int = 5 * 1024 * 1024

    # URL Analysis Configuration
    URL_ANALYSIS_ML_ENABLED: bool = True
    URL_ANALYSIS_ML_API_URL: str = ""
    URL_ANALYSIS_ML_TIMEOUT_SECONDS: int = 20
    URL_ANALYSIS_THREAT_INTEL_ENABLED: bool = True
    URL_ANALYSIS_THREAT_INTEL_API_URL: str = ""
    URL_ANALYSIS_THREAT_INTEL_API_KEY: str = ""
    URL_ANALYSIS_THREAT_INTEL_TIMEOUT_SECONDS: int = 5
    URL_ANALYSIS_THREAT_INTEL_CACHE_TTL_SECONDS: int = 1800
    URL_ANALYSIS_THREAT_INTEL_DOMAINS: str = ""
    URL_ANALYSIS_THREAT_INTEL_SUFFIXES: str = ""

    # URL Caching Configuration
    URL_ANALYSIS_CACHE_ENABLED: bool = True
    URL_ANALYSIS_CACHE_TTL_HOURS: int = 24

    # Dynamic URL Analysis Configuration
    URL_ANALYSIS_TLS_LOOKUP_ENABLED: bool = False
    URL_ANALYSIS_DYNAMIC_TIMEOUT_SECONDS: int = 6
    URL_ANALYSIS_SCREENSHOT_SERVICE_URL: str = ""
    URL_ANALYSIS_SCREENSHOT_SERVICE_TIMEOUT_SECONDS: int = 25
    URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY: str = ""
    URL_ANALYSIS_SCREENSHOT_LOCAL_FALLBACK_ENABLED: bool = True
    URL_ANALYSIS_SCREENSHOT_LOCAL_TIMEOUT_SECONDS: int = 20
    URL_ANALYSIS_SCREENSHOT_CAPTURE_MODE: str = "local_first"
    URL_ANALYSIS_DYNAMIC_FAST_MODE: bool = False

    # CORS origins
    ALLOWED_ORIGINS: Set[str] = {
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "https://dark-hook-defense.vercel.app",
        "https://darkhookdefense.online",
        "https://www.darkhookdefense.online",
    }

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def get_cors_origins(self) -> list[str]:
        origins = set(self.ALLOWED_ORIGINS)
        if self.FRONTEND_URL:
            origins.add(self.FRONTEND_URL)
        return sorted(list(origins))

settings = Settings()
