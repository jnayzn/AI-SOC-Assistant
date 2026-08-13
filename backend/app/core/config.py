"""Application configuration loaded from environment variables (.env)."""
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

# Kept as a module-level constant (not a class attribute) so it is never at
# risk of being picked up as a pydantic model field/private-attr.
_INSECURE_SECRET_KEY_DEFAULT = "insecure-dev-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "AI-Powered Security Triage Assistant"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    SECRET_KEY: str = "insecure-dev-secret-change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    POSTGRES_USER: str = "triage_user"
    POSTGRES_PASSWORD: str = "triage_password"
    POSTGRES_DB: str = "triage_assistant"
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = ""

    # --- LLM provider selection ---
    # "openai": uses OpenAI's hosted API (requires OPENAI_API_KEY + credits).
    # "ollama": uses a local Ollama server via its OpenAI-compatible endpoint
    #           (free, runs on your machine, no API key required). This is
    #           the default so the project runs out of the box without an
    #           OpenAI key, as long as Ollama is installed and running.
    LLM_PROVIDER: str = "ollama"

    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_TEMPERATURE: float = 0.1

    # --- Ollama (used when LLM_PROVIDER=ollama) ---
    # host.docker.internal lets the backend container reach Ollama running on
    # the host machine (Windows/Mac Docker Desktop support this natively; on
    # Linux the docker-compose.yml adds an extra_hosts entry for it too).
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434/v1"
    # Defaults to a lightweight, text-only model that is well supported by
    # Ollama. Avoid "llama3.2-vision" here: it uses the "mllama" architecture,
    # which many Ollama installs fail to load ("unknown model architecture:
    # 'mllama'") unless Ollama is fully up to date. Since this app only
    # analyzes text (emails/logs), a vision model is unnecessary anyway.
    OLLAMA_MODEL: str = "llama3.2:3b"

    RATE_LIMIT_PER_MINUTE: int = 20

    CHROMA_PERSIST_DIR: str = "/app/data/chroma"

    # --- Threat Intelligence (optional) ---
    # Used for live IOC enrichment lookups (VirusTotal file/URL/IP/domain
    # reputation, Shodan host/port intelligence, AbuseIPDB IP reputation).
    # Leave a key blank to keep that source's card in "not configured" mode
    # in the Analyzer's Threat Intelligence panel.
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    # How long a successful VirusTotal/Shodan/AbuseIPDB lookup result is
    # reused before looking the same indicator up again. Keeps repeated
    # indicators across analyses from burning through free-tier API quotas.
    THREAT_INTEL_CACHE_TTL_HOURS: int = 12

    # --- Notifications (optional) ---
    # Incoming webhook URL (e.g. Slack) notified best-effort whenever an
    # analysis is classified Critical. Leave blank to disable.
    SLACK_WEBHOOK_URL: str = ""

    # --- IntelOwl Threat Intelligence integration ---
    INTELOWL_URL: str = "http://host.docker.internal"
    INTELOWL_API_TOKEN: str = ""
    INTELOWL_TIMEOUT: int = 120
    INTELOWL_VERIFY_SSL: bool = False
    INTELOWL_CACHE_TTL_SECONDS: int = 3600
    INTELOWL_DEFAULT_PLAYBOOK: str = ""

    @property
    def intelowl_base_url(self) -> str:
        return (self.INTELOWL_URL or "").rstrip("/")

    @property
    def intelowl_configured(self) -> bool:
        return bool(self.intelowl_base_url and self.INTELOWL_API_TOKEN)

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def has_insecure_secret_key(self) -> bool:
        """True when SECRET_KEY is still the shipped placeholder value.

        Used at startup to loudly warn (or refuse to start in production)
        rather than silently issuing forgeable JWTs.
        """
        return self.SECRET_KEY == _INSECURE_SECRET_KEY_DEFAULT

    @property
    def sqlalchemy_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
