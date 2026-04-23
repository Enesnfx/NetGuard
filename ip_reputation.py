"""
AbuseIPDB reputation checker.

- API key stored in config.json, loaded once at startup.
- Results cached to .ip_cache.json on disk — IPs are NEVER re-queried
  once a result is stored (permanent cache; delete .ip_cache.json to reset).
- Private/reserved IPs are skipped automatically.
"""
import os
import json
import time
import ipaddress
import requests

_DIR        = os.path.dirname(os.path.abspath(__file__))
_CACHE_FILE = os.path.join(_DIR, ".ip_cache.json")
API_URL     = "https://api.abuseipdb.com/api/v2/check"

_api_key: str = ""
_cache: dict  = {}   # { ip: {result dict} } — permanent, no TTL


# ── cache I/O ──────────────────────────────────────────────────────────────
def _load_cache():
    global _cache
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, encoding="utf-8") as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    return _cache


def _save_cache():
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass


# Load disk cache on module import so every session reuses prior lookups
_load_cache()


# ── public API ─────────────────────────────────────────────────────────────
def set_api_key(key: str):
    global _api_key
    _api_key = key.strip()


def check_ip(ip: str) -> dict:
    """
    Return abuse data for ip.
    Cache hit → return immediately, no API call.
    Cache miss → query AbuseIPDB, store permanently, return result.
    Private IPs or missing key → return zero result instantly.
    """
    if not _api_key or _is_private(ip):
        return _empty(ip)

    # Permanent cache — never re-check
    if ip in _cache:
        return _cache[ip]

    try:
        resp = requests.get(
            API_URL,
            headers={"Accept": "application/json", "Key": _api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            result = {
                "ip":            ip,
                "abuse_score":   d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", "Never"),
                "country":       d.get("countryCode", ""),
                "checked_at":    time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            result = _empty(ip)

        _cache[ip] = result
        _save_cache()
        return result

    except Exception:
        return _empty(ip)


def is_cached(ip: str) -> bool:
    return ip in _cache


def cache_size() -> int:
    return len(_cache)


def clear_cache():
    global _cache
    _cache = {}
    if os.path.exists(_CACHE_FILE):
        os.remove(_CACHE_FILE)


# ── helpers ────────────────────────────────────────────────────────────────
def _empty(ip: str) -> dict:
    return {
        "ip": ip, "abuse_score": 0, "total_reports": 0,
        "last_reported": "N/A", "country": "",
        "checked_at": "",
    }


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True
