"""
Google Safe Browsing API v4 integration.
The API key is always read fresh from config.py — no module-level caching.
"""

import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_api_key() -> str:
    """Return the API key fresh from config every call (avoids caching bugs)."""
    # Import inside function so the key is always current
    import importlib
    import src.config as cfg
    importlib.reload(cfg)            # reload in case config was patched at runtime
    return (cfg.GOOGLE_SAFE_BROWSING_API_KEY or "").strip()


def is_safe_browsing_configured() -> bool:
    return bool(_get_api_key())


def check_url_safe_browsing(url: str) -> dict:
    """
    Check a URL against Google Safe Browsing API v4.

    Returns a dict:
        {
            "checked": bool,       # False if API not configured or request failed
            "is_malicious": bool,
            "threats": list[str],  # e.g. ["MALWARE", "SOCIAL_ENGINEERING"]
            "error": str | None,
        }
    """
    result = {
        "checked": False,
        "is_malicious": False,
        "threats": [],
        "error": None,
    }

    api_key = _get_api_key()
    if not api_key:
        result["error"] = "Google Safe Browsing API key not configured."
        return result

    from src.config import (
        SAFE_BROWSING_ENDPOINT,
        THREAT_TYPES,
        PLATFORM_TYPES,
        THREAT_ENTRY_TYPES,
    )

    payload = {
        "client": {
            "clientId": "threatlens",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        result["checked"] = True
        matches = data.get("matches", [])
        if matches:
            result["is_malicious"] = True
            result["threats"] = list({m.get("threatType", "") for m in matches})
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        result["error"] = f"Safe Browsing API HTTP error {status}: {e}"
        logger.warning(result["error"])
    except requests.exceptions.RequestException as e:
        result["error"] = f"Safe Browsing API request failed: {e}"
        logger.warning(result["error"])
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.exception(result["error"])

    return result
