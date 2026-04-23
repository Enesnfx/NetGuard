import json
import os
from datetime import datetime

_PATH = os.path.join(os.path.dirname(__file__), "whitelist.json")


def _load() -> dict:
    if not os.path.exists(_PATH):
        return {}
    try:
        with open(_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    with open(_PATH, "w") as f:
        json.dump(data, f, indent=2)


def add(mac: str, label: str = "", ip: str = ""):
    d = _load()
    d[mac.upper()] = {"label": label, "ip": ip, "added": datetime.now().isoformat()}
    _save(d)


def remove(mac: str):
    d = _load()
    d.pop(mac.upper(), None)
    _save(d)


def is_whitelisted(mac: str) -> bool:
    return mac.upper() in _load()


def get_label(mac: str) -> str:
    return _load().get(mac.upper(), {}).get("label", "")


def get_all() -> dict:
    return _load()
