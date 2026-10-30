from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    slack_webhook_url: str = ""
    canary_base_url: str = "http://localhost:8000"
    db_path: str = "dlp.db"
    decoy_store_dir: str = "decoys_store"
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    ai_model: str = "claude-opus-5-5"
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
