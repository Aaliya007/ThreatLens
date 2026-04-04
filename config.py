# ============================================================
# ThreatLens Configuration
# ============================================================
# >>> ADD YOUR API KEY HERE <<<
# Replace the empty string below with your Google Safe Browsing API key.
# Example: GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyABC123..."

GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCPOYzXfsyGr31zOjy7SLF_BAcjgIxSSTc"   # <-- PASTE YOUR API KEY BETWEEN THE QUOTES

# ============================================================
# Do NOT change anything below this line
# ============================================================

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]

THREAT_ENTRY_TYPES = ["URL"]

RISK_THRESHOLDS = {
    "LOW": 30,
    "MEDIUM": 60,
    "HIGH": 80,
}

APP_TITLE = "ThreatLens"
APP_ICON  = "🔍"
APP_VERSION = "1.0.0"
