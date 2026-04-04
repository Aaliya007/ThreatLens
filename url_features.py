"""
Lexical / heuristic URL feature extraction for ThreatLens.
No changes to original logic — only code is reorganised for clarity.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict, Any

# Suspicious keywords found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "paypal", "amazon", "google", "apple", "microsoft", "netflix", "ebay",
    "password", "confirm", "validation", "wallet", "alert", "suspend",
    "unusual", "activity", "click", "free", "win", "prize", "lucky",
    "offer", "limited", "urgent", "immediately", "credit", "debit",
]

# Legit TLDs that are sometimes spoofed in subdomains
TRUSTED_DOMAINS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "twitter", "instagram", "netflix", "ebay", "linkedin", "dropbox",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "short.io", "rebrand.ly", "tiny.cc",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def extract_features(url: str) -> Dict[str, Any]:
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    except Exception:
        return {}

    domain    = parsed.netloc.lower()
    path      = parsed.path.lower()
    full_url  = url.lower()

    # Basic counts
    url_length     = len(url)
    dot_count      = full_url.count(".")
    hyphen_count   = domain.count("-")
    digit_count    = sum(c.isdigit() for c in domain)
    special_chars  = len(re.findall(r"[!@#$%^&*(){}\[\]|\\<>]", url))
    subdomain_cnt  = len(domain.split(".")) - 2 if domain.count(".") >= 2 else 0

    # Flags
    has_ip         = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain))
    has_https      = parsed.scheme == "https"
    has_at         = "@" in url
    has_double_slash = "//" in path
    has_shortener  = any(s in domain for s in URL_SHORTENERS)
    suspicious_kw  = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    brand_in_sub   = any(
        b in domain.replace(domain.split(".")[-2] + "." + domain.split(".")[-1], "")
        for b in TRUSTED_DOMAINS
        if domain.count(".") >= 2
    )

    ent = _entropy(domain)

    features = {
        "url_length":       url_length,
        "dot_count":        dot_count,
        "hyphen_count":     hyphen_count,
        "digit_count":      digit_count,
        "special_chars":    special_chars,
        "subdomain_count":  subdomain_cnt,
        "has_ip":           has_ip,
        "has_https":        has_https,
        "has_at_symbol":    has_at,
        "has_double_slash": has_double_slash,
        "is_url_shortener": has_shortener,
        "suspicious_keywords": suspicious_kw,
        "brand_in_subdomain": brand_in_sub,
        "domain_entropy":   round(ent, 3),
        "domain":           domain,
        "path":             path,
    }
    return features


def calculate_risk_score(features: Dict[str, Any]) -> int:
    """
    Heuristic risk score 0–100 based on extracted URL features.
    """
    score = 0

    # --- Length ---
    length = features.get("url_length", 0)
    if length > 75:
        score += 10
    if length > 100:
        score += 10

    # --- Dots ---
    if features.get("dot_count", 0) > 4:
        score += 10

    # --- Hyphens ---
    if features.get("hyphen_count", 0) >= 2:
        score += 10

    # --- Digits in domain ---
    if features.get("digit_count", 0) >= 3:
        score += 10

    # --- Special chars ---
    if features.get("special_chars", 0) > 0:
        score += 15

    # --- Subdomains ---
    if features.get("subdomain_count", 0) >= 3:
        score += 15

    # --- IP address ---
    if features.get("has_ip"):
        score += 20

    # --- No HTTPS ---
    if not features.get("has_https"):
        score += 10

    # --- @ symbol ---
    if features.get("has_at_symbol"):
        score += 15

    # --- Double slash in path ---
    if features.get("has_double_slash"):
        score += 10

    # --- URL shortener ---
    if features.get("is_url_shortener"):
        score += 15

    # --- Suspicious keywords ---
    kw_count = len(features.get("suspicious_keywords", []))
    score += min(kw_count * 5, 20)

    # --- Brand spoofing ---
    if features.get("brand_in_subdomain"):
        score += 20

    # --- High domain entropy ---
    if features.get("domain_entropy", 0) > 4.0:
        score += 10

    return min(score, 100)


def get_risk_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    if score >= 30:
        return "LOW"
    return "SAFE"


def get_risk_reasons(features: Dict[str, Any], score: int) -> list:
    reasons = []

    if features.get("has_ip"):
        reasons.append("🔴 Domain is a raw IP address — commonly used in phishing")
    if features.get("brand_in_subdomain"):
        reasons.append("🔴 Trusted brand name found in subdomain — possible spoofing")
    if features.get("subdomain_count", 0) >= 3:
        reasons.append("🟠 Excessive subdomain depth detected")
    if features.get("is_url_shortener"):
        reasons.append("🟠 URL shortener detected — hides true destination")
    if features.get("has_at_symbol"):
        reasons.append("🟠 '@' symbol in URL can mislead users about destination")
    if features.get("special_chars", 0) > 0:
        reasons.append("🟠 Unusual special characters found in URL")
    if not features.get("has_https"):
        reasons.append("🟡 No HTTPS — connection is not encrypted")
    kws = features.get("suspicious_keywords", [])
    if kws:
        reasons.append(f"🟡 Suspicious keywords: {', '.join(kws[:5])}")
    if features.get("domain_entropy", 0) > 4.0:
        reasons.append("🟡 High domain name entropy — possible random/generated domain")
    if features.get("hyphen_count", 0) >= 2:
        reasons.append("🟡 Multiple hyphens in domain")
    if features.get("url_length", 0) > 100:
        reasons.append("🟡 Very long URL (obfuscation indicator)")

    if not reasons:
        reasons.append("✅ No major heuristic risk factors detected")

    return reasons
