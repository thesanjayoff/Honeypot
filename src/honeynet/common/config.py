"""Configuration: defaults < optional YAML file < environment variables.

Env vars are all prefixed ``HONEYNET_``.  Secrets are only ever read from the
environment (never from the YAML file) so config files can be committed/shared.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .redact import Redactor

DEFAULT_PORTS = {
    "ssh": [2222],
    "telnet": [2323],
    "http": [8080],
    "mysql": [3306],
    "redis": [6379],
}


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on", "y"}


def _csv(v: Any) -> list[str]:
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


@dataclass
class Settings:
    data_dir: Path = Path("/data")
    test_mode: bool = False
    bind_host: str = "0.0.0.0"

    # --- operator privacy ---
    ignore_src: list[str] = field(default_factory=list)  # admin IPs/CIDRs, never logged/exported
    extra_secrets: list[str] = field(default_factory=list)

    # --- limits (everything an attacker controls is bounded) ---
    max_session_seconds: int = 300
    max_idle_seconds: int = 60
    max_conns_total: int = 200
    max_conns_per_ip: int = 8
    max_file_bytes: int = 10 * 1024 * 1024
    max_quarantine_bytes: int = 2 * 1024 * 1024 * 1024
    max_http_body: int = 1024 * 1024
    max_events_per_ip_minute: int = 600
    max_events_dir_bytes: int = 512 * 1024 * 1024

    # --- outbound (default: none). Honeypot containers never talk to the internet;
    #     downloads are delegated to the sandboxed fetcher service, if enabled. ---
    fetcher_url: str = ""          # e.g. http://fetcher:8099 ; empty disables real downloads
    fetcher_token: str = ""
    fetcher_max_per_session: int = 4

    # --- per service ---
    ports: dict[str, list[int]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_PORTS.items()})
    ssh_accept_pct: int = 12        # % of unknown user/password combos that "work"
    persona: dict[str, Any] = field(default_factory=dict)

    # --- dashboard ---
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8088
    dashboard_password: str = ""
    dashboard_password_hash: str = ""
    dashboard_secret: str = ""
    dashboard_allowed_hosts: list[str] = field(default_factory=list)   # extra Host headers (besides localhost/bind host)
    dashboard_cookie_secure: bool = False                                # set when served over https (tunnel -> false)
    dashboard_session_hours: int = 12
    retention_days: int = 90
    ingest_poll_seconds: float = 1.0
    geoip_dir: Path | None = None
    abuseipdb_enabled: bool = False
    abuseipdb_key: str = ""
    abuseipdb_daily_limit: int = 900
    bazaar_enabled: bool = False
    bazaar_key: str = ""

    # --- alerts ---
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)
    alert_cooldown_seconds: int = 600
    spike_factor: float = 4.0
    spike_min_events: int = 60

    # --- analysis ---
    analysis_backend: str = "builtin"      # builtin | command
    analysis_command: str = ""             # for backend=command
    analysis_timeout: int = 60
    analysis_max_bytes: int = 25 * 1024 * 1024
    analysis_poll_seconds: int = 5

    # ---- derived paths ----
    @property
    def events_dir(self) -> Path:
        return self.data_dir / "events"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def analysis_dir(self) -> Path:
        return self.data_dir / "analysis"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "db" / "honeynet.sqlite3"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    def secrets(self) -> list[str]:
        vals = [
            self.dashboard_password, self.dashboard_secret, self.abuseipdb_key, self.bazaar_key,
            self.webhook_url, self.smtp_password, self.fetcher_token, *self.extra_secrets,
        ]
        return [v for v in vals if v]

    def redactor(self) -> Redactor:
        return Redactor(self.ignore_src, self.secrets())

    def service_ports(self, name: str) -> list[int]:
        return list(self.ports.get(name, []))


_ENV_MAP: dict[str, tuple[str, Any]] = {
    "DATA_DIR": ("data_dir", Path),
    "TEST_MODE": ("test_mode", _truthy),
    "BIND_HOST": ("bind_host", str),
    "IGNORE_SRC": ("ignore_src", _csv),
    "EXTRA_SECRETS": ("extra_secrets", _csv),
    "MAX_SESSION_SECONDS": ("max_session_seconds", int),
    "MAX_IDLE_SECONDS": ("max_idle_seconds", int),
    "MAX_CONNS_TOTAL": ("max_conns_total", int),
    "MAX_CONNS_PER_IP": ("max_conns_per_ip", int),
    "MAX_FILE_BYTES": ("max_file_bytes", int),
    "MAX_QUARANTINE_BYTES": ("max_quarantine_bytes", int),
    "MAX_HTTP_BODY": ("max_http_body", int),
    "FETCHER_URL": ("fetcher_url", str),
    "FETCHER_TOKEN": ("fetcher_token", str),
    "FETCHER_MAX_PER_SESSION": ("fetcher_max_per_session", int),
    "SSH_ACCEPT_PCT": ("ssh_accept_pct", int),
    "DASHBOARD_HOST": ("dashboard_host", str),
    "DASHBOARD_PORT": ("dashboard_port", int),
    "DASHBOARD_PASSWORD": ("dashboard_password", str),
    "DASHBOARD_PASSWORD_HASH": ("dashboard_password_hash", str),
    "DASHBOARD_SECRET": ("dashboard_secret", str),
    "DASHBOARD_ALLOWED_HOSTS": ("dashboard_allowed_hosts", _csv),
    "DASHBOARD_COOKIE_SECURE": ("dashboard_cookie_secure", _truthy),
    "DASHBOARD_SESSION_HOURS": ("dashboard_session_hours", int),
    "RETENTION_DAYS": ("retention_days", int),
    "INGEST_POLL_SECONDS": ("ingest_poll_seconds", float),
    "GEOIP_DIR": ("geoip_dir", Path),
    "ABUSEIPDB_ENABLED": ("abuseipdb_enabled", _truthy),
    "ABUSEIPDB_KEY": ("abuseipdb_key", str),
    "ABUSEIPDB_DAILY_LIMIT": ("abuseipdb_daily_limit", int),
    "BAZAAR_ENABLED": ("bazaar_enabled", _truthy),
    "BAZAAR_KEY": ("bazaar_key", str),
    "WEBHOOK_URL": ("webhook_url", str),
    "SMTP_HOST": ("smtp_host", str),
    "SMTP_PORT": ("smtp_port", int),
    "SMTP_USER": ("smtp_user", str),
    "SMTP_PASSWORD": ("smtp_password", str),
    "SMTP_FROM": ("smtp_from", str),
    "SMTP_TO": ("smtp_to", _csv),
    "ALERT_COOLDOWN_SECONDS": ("alert_cooldown_seconds", int),
    "SPIKE_FACTOR": ("spike_factor", float),
    "SPIKE_MIN_EVENTS": ("spike_min_events", int),
    "ANALYSIS_BACKEND": ("analysis_backend", str),
    "ANALYSIS_COMMAND": ("analysis_command", str),
    "ANALYSIS_TIMEOUT": ("analysis_timeout", int),
    "ANALYSIS_MAX_BYTES": ("analysis_max_bytes", int),
}

# YAML must never carry secrets
_SECRET_FIELDS = {
    "dashboard_password", "dashboard_password_hash", "dashboard_secret", "abuseipdb_key", "bazaar_key",
    "webhook_url", "smtp_password", "fetcher_token", "extra_secrets",
}


def load_settings(env: dict[str, str] | None = None, yaml_path: str | os.PathLike | None = None) -> Settings:
    env = dict(os.environ if env is None else env)
    s = Settings()

    path = yaml_path or env.get("HONEYNET_CONFIG")
    if path and Path(path).is_file():
        import yaml  # local import: keep honeypot images lean if yaml is absent

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for key, val in raw.items():
            if key in _SECRET_FIELDS or not hasattr(s, key):
                continue
            if key == "ports" and isinstance(val, dict):
                s.ports.update({k: [int(p) for p in v] for k, v in val.items()})
            elif key in ("data_dir", "geoip_dir"):
                setattr(s, key, Path(val))
            else:
                setattr(s, key, val)

    for suffix, (attr, conv) in _ENV_MAP.items():
        v = env.get(f"HONEYNET_{suffix}")
        if v is None or v == "":
            continue
        try:
            setattr(s, attr, conv(v))
        except (ValueError, TypeError):
            raise SystemExit(f"invalid value for HONEYNET_{suffix}: {v!r}")

    for name in list(s.ports):
        v = env.get(f"HONEYNET_PORTS_{name.upper()}")
        if v:
            s.ports[name] = [int(p) for p in _csv(v)]
    # plugin services may declare ports through env even if unknown by default
    for k, v in env.items():
        if k.startswith("HONEYNET_PORTS_"):
            name = k[len("HONEYNET_PORTS_"):].lower()
            s.ports.setdefault(name, [int(p) for p in _csv(v)])

    s.data_dir = Path(s.data_dir)
    if s.geoip_dir:
        s.geoip_dir = Path(s.geoip_dir)
    return s
