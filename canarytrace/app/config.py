from pydantic_settings import BaseSettings, SettingsConfigDict
import ipaddress
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    slack_webhook_url: str = ""
    canary_base_url: str = "http://localhost:8000"
    anthropic_api_key: str = ""
    cors_origins: str = "http://localhost:5173"
    corporate_networks: str = '127.0.0.0/8,::1/128'
    trusted_proxies: str = ''
    canary_external_alerts: bool = True
    canary_tracking_enabled: bool = True

    @field_validator('corporate_networks', 'trusted_proxies')
    @classmethod
    def validate_networks(cls, value):
        # IPv4·IPv6 CIDR 문법을 기동 시 검증합니다. 사설 IP라는 이유만으로 사내망으로 보지 않습니다.
        return ','.join(str(ipaddress.ip_network(n.strip())) for n in value.split(',') if n.strip())

    @property
    def corporate_network_list(self):
        return [n for n in self.corporate_networks.split(',') if n]

    @property
    def trusted_proxy_list(self):
        return [n for n in self.trusted_proxies.split(',') if n]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
