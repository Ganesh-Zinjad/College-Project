"""
Centralized configuration.

Every other module reads configuration from `settings` (a singleton) instead
of calling `os.environ` directly. This keeps environment-variable parsing in
exactly one place and gives free validation: a malformed .env fails fast at
startup instead of producing confusing runtime errors deep inside a service.
"""
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- App ---
    APP_NAME: str = "Secure Code Vulnerability Detection Platform"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    FRONTEND_ORIGIN: str = "http://localhost:5500"

    # --- Security / JWT ---
    SECRET_KEY: str = "dev-only-secret-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./secure_code_platform.db"

    # --- Email ---
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_NAME: str = "Secure Code Platform"
    SMTP_FROM_EMAIL: str = "no-reply@securecode.dev"
    SMTP_USE_TLS: bool = True

    # --- Engine 1: CodeQL ---
    CODEQL_CLI_PATH: str = "/usr/local/bin/codeql"
    CODEQL_QUERY_SUITE: str = "security-extended"
    CODEQL_DB_DIR: str = "./codeql_dbs"
    CODEQL_TIMEOUT_SECONDS: int = 300

    # =========================================================================
    # --- Engine 2 / Explainable AI: LLM Provider ---
    #
    # Set AI_PROVIDER to one of:  anthropic | openai | gemini
    # Then supply the matching API key below.
    # Only the SDK for the chosen provider needs to be installed.
    # =========================================================================
    AI_PROVIDER: str = "anthropic"          # anthropic | openai | gemini

    # Anthropic (Claude) — https://console.anthropic.com/
    ANTHROPIC_API_KEY: str = ""
    AI_AUDIT_MODEL: str = "claude-sonnet-4-6"   # Claude model to use
    AI_AUDIT_MAX_TOKENS: int = 4096

    # OpenAI (GPT) — https://platform.openai.com/
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"               # gpt-4o | gpt-4-turbo | gpt-4 | gpt-3.5-turbo

    # Google Gemini — https://aistudio.google.com/
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-pro"       # gemini-1.5-pro | gemini-1.5-flash | gemini-pro

    # --- Engine 3: ML Classifier ---
    ML_MODEL_PATH: str = "./ml_artifacts/vuln_classifier.joblib"
    ML_VECTORIZER_PATH: str = "./ml_artifacts/vectorizer.joblib"
    ML_CONFIDENCE_THRESHOLD: float = 0.55

    # --- Uploads ---
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_EXTENSIONS: str = ".py,.js,.ts,.java,.go,.rb,.php,.c,.cpp,.cs,.zip"

    # --- Rate limiting ---
    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def allowed_extensions_list(self) -> List[str]:
        return [ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()]

    @property
    def cors_origins(self) -> List[str]:
        defaults = {
            self.FRONTEND_ORIGIN,
            "http://localhost:5500",
            "http://127.0.0.1:5500",
            "http://[::1]:5500",
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
        }
        return [o for o in defaults if o]

    @property
    def active_ai_provider(self) -> str:
        """Normalized provider name (lowercase, stripped)."""
        return (self.AI_PROVIDER or "anthropic").lower().strip()


@lru_cache
def get_settings() -> Settings:
    """Settings are read once and cached — env vars don't change at runtime."""
    return Settings()


settings = get_settings()
