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

    # Brevo API & Email Sender Configuration
    BREVO_API_KEY: str | None = None
    BREVO_API_URL: str = "https://api.brevo.com/v3/smtp/email"
    BREVO_SENDER_EMAIL: str | None = None
    BREVO_SENDER_NAME: str = "DarkHook Defense"
    SMTP_FROM: str | None = None  # Backward-compatible fallback for sender email/name

    # Scan File Limits
    MAX_DOCUMENT_UPLOAD_BYTES: int = 10 * 1024 * 1024
    MAX_EMAIL_UPLOAD_BYTES: int = 5 * 1024 * 1024

    # URL Analysis Configuration
    URL_ANALYSIS_ML_ENABLED: bool = True
    URL_ANALYSIS_ML_API_URL: str = ""
    URL_ANALYSIS_ML_TIMEOUT_SECONDS: int = 20
    URL_ANALYSIS_LOCAL_ML_ENABLED: bool = True
    URL_ANALYSIS_THREAT_INTEL_ENABLED: bool = True
    URL_ANALYSIS_THREAT_INTEL_API_URL: str = ""
    URL_ANALYSIS_THREAT_INTEL_API_KEY: str = ""
    URL_ANALYSIS_THREAT_INTEL_TIMEOUT_SECONDS: int = 5
    URL_ANALYSIS_THREAT_INTEL_CACHE_TTL_SECONDS: int = 1800
    URL_ANALYSIS_THREAT_INTEL_DOMAINS: str = ""
    URL_ANALYSIS_THREAT_INTEL_SUFFIXES: str = ""
    URL_ANALYSIS_RDAP_ENABLED: bool = True
    URL_ANALYSIS_RDAP_TIMEOUT_SECONDS: int = 4
    URL_ANALYSIS_URLHAUS_ENABLED: bool = True
    URL_ANALYSIS_URLHAUS_API_KEY: str = ""
    URL_ANALYSIS_URLHAUS_TIMEOUT_SECONDS: int = 4
    URL_ANALYSIS_FAVICON_ENABLED: bool = True

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

    # Additional Trusted Domains & Custom Whitelist
    ADDITIONAL_TRUSTED_DOMAINS: str = ""

    # VirusTotal Checker Configuration
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_REQUEST_INTERVAL_SECONDS: int = 16
    VIRUSTOTAL_POLL_INTERVAL_SECONDS: int = 15
    VIRUSTOTAL_RATE_LIMIT_BACKOFF_SECONDS: int = 60

    # Persistence & DNS Settings
    SQLITE_DB_PATH: str = ""
    DNS_NAMESERVERS: str = "8.8.8.8,1.1.1.1,8.8.4.4"

    # CORS origins
    CORS_ALLOWED_ORIGINS: str = ""
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
        if self.CORS_ALLOWED_ORIGINS:
            for item in self.CORS_ALLOWED_ORIGINS.split(","):
                cleaned = item.strip()
                if cleaned:
                    origins.add(cleaned)
        if self.FRONTEND_URL:
            origins.add(self.FRONTEND_URL)
        return sorted(list(origins))

settings = Settings()
