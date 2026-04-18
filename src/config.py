# ============================================================
# ThreatLens Configuration
# ============================================================
import os
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

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
