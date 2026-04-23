import json
import os

_PATH = os.path.join(os.path.dirname(__file__), "config.json")

_DEFAULTS = {
    "abuseipdb_api_key": "",
    "scan_interval_minutes": 30,
    "auto_scan_on_start": False,
    "notifications_enabled": True,
}


def load() -> dict:
    if not os.path.exists(_PATH):
        return dict(_DEFAULTS)
    try:
        with open(_PATH) as f:
            return {**_DEFAULTS, **json.load(f)}
    except Exception:
        return dict(_DEFAULTS)


def save(cfg: dict):
    with open(_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def get(key: str):
    return load().get(key, _DEFAULTS.get(key))


def set_value(key: str, value):
    cfg = load()
    cfg[key] = value
    save(cfg)
