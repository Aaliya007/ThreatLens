"""
ThreatLens — Malicious URL Scanner
Streamlit application entry point.
"""

import streamlit as st
import pandas as pd
import io
from src.url_features import extract_features, calculate_risk_score, get_risk_label, get_risk_reasons
from src.safe_browsing import check_url_safe_browsing, is_safe_browsing_configured
from src.config import APP_TITLE, APP_ICON, APP_VERSION

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title=APP_TITLE,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #e74c3c;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1rem;
        color: #7f8c8d;
        margin-top: 0;
        margin-bottom: 2rem;
    }
    .risk-high {
        background: linear-gradient(135deg, #e74c3c22, #c0392b11);
        border-left: 4px solid #e74c3c;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    .risk-medium {
        background: linear-gradient(135deg, #f39c1222, #e67e2211);
        border-left: 4px solid #f39c12;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    .risk-low {
        background: linear-gradient(135deg, #f1c40f22, #f39c1211);
        border-left: 4px solid #f1c40f;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    .risk-safe {
        background: linear-gradient(135deg, #2ecc7122, #27ae6011);
        border-left: 4px solid #2ecc71;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    .feature-card {
        background: #1a1a2e;
        border: 1px solid #16213e;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.25rem 0;
    }
    .api-status-ok  { color: #2ecc71; font-weight: 600; }
    .api-status-err { color: #e74c3c; font-weight: 600; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"## {APP_ICON} {APP_TITLE}")
    st.markdown(f"*Version {APP_VERSION}*")
    st.divider()

    st.markdown("### 🛡️ Detection Engines")
    st.markdown("✅ **Heuristic / Lexical Analysis** — always active")

    if is_safe_browsing_configured():
        st.markdown('<p class="api-status-ok">✅ Google Safe Browsing — Active</p>', unsafe_allow_html=True)
    else:
        st.markdown('<p class="api-status-err">⚠️ Google Safe Browsing — Not configured</p>', unsafe_allow_html=True)
        st.info("Open **src/config.py** and paste your API key into `GOOGLE_SAFE_BROWSING_API_KEY`.")

    st.divider()
    st.markdown("### 📊 Risk Levels")
    st.markdown("🔴 **HIGH** — Score ≥ 80  \n🟠 **MEDIUM** — Score 60–79  \n🟡 **LOW** — Score 30–59  \n🟢 **SAFE** — Score < 30")
    st.divider()
    st.markdown("### ℹ️ About")
    st.markdown("ThreatLens combines **lexical heuristics** with the **Google Safe Browsing API** to detect malicious URLs in real time.")


# ── Main Header ────────────────────────────────────────────────────────────────
st.markdown('<h1 class="main-header">🔍 ThreatLens</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">AI-Powered Malicious URL Detection</p>', unsafe_allow_html=True)


# ── Tabs ───────────────────────────────────────────────────────────────────────
tab_single, tab_batch = st.tabs(["🔗 Single URL Scan", "📋 Batch URL Scan"])


# ──────────────────────────────────────────────────────────────────────────────
# TAB 1 — Single URL
# ──────────────────────────────────────────────────────────────────────────────
with tab_single:
    st.markdown("### Enter a URL to scan")
    url_input = st.text_input(
        "URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )

    col_scan, col_clear = st.columns([1, 5])
    with col_scan:
        scan_clicked = st.button("🔍 Scan URL", use_container_width=True, type="primary")

    if scan_clicked and url_input.strip():
        url = url_input.strip()
        with st.spinner("Analysing URL…"):
            features   = extract_features(url)
            heur_score = calculate_risk_score(features)
            risk_label = get_risk_label(heur_score)
            reasons    = get_risk_reasons(features, heur_score)
            sb_result  = check_url_safe_browsing(url)

        # ── Composite score ──
        final_score = heur_score
        is_confirmed_malicious = False
        if sb_result["checked"] and sb_result["is_malicious"]:
            is_confirmed_malicious = True
            final_score = max(heur_score, 90)
            risk_label  = "HIGH"

        # ── Risk banner ──
        css_class = f"risk-{risk_label.lower()}"
        emoji_map = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "SAFE": "🟢"}
        st.markdown(
            f'<div class="{css_class}"><strong>{emoji_map[risk_label]} Risk Level: {risk_label}</strong> &nbsp;|&nbsp; Score: {final_score}/100</div>',
            unsafe_allow_html=True,
        )

        if is_confirmed_malicious:
            st.error(f"🚨 **Confirmed Threat** — Google Safe Browsing flagged this URL!\nThreat types: {', '.join(sb_result['threats'])}")
        elif sb_result["checked"]:
            st.success("✅ Google Safe Browsing: No threats found.")
        elif sb_result["error"]:
            st.warning(f"⚠️ Safe Browsing check skipped: {sb_result['error']}")

        st.divider()

        # ── Two columns: reasons + features ──
        col_r, col_f = st.columns(2)
        with col_r:
            st.markdown("#### 🔎 Risk Reasons")
            for r in reasons:
                st.markdown(f"- {r}")

        with col_f:
            st.markdown("#### 📐 URL Features")
            feat_display = {
                "URL Length":       features.get("url_length"),
                "Has HTTPS":        features.get("has_https"),
                "IP as Domain":     features.get("has_ip"),
                "Subdomains":       features.get("subdomain_count"),
                "Hyphens":          features.get("hyphen_count"),
                "Dots":             features.get("dot_count"),
                "Digits in Domain": features.get("digit_count"),
                "@ Symbol":         features.get("has_at_symbol"),
                "URL Shortener":    features.get("is_url_shortener"),
                "Domain Entropy":   features.get("domain_entropy"),
                "Special Chars":    features.get("special_chars"),
                "Brand in Subdomain": features.get("brand_in_subdomain"),
            }
            feat_df = pd.DataFrame(feat_display.items(), columns=["Feature", "Value"])
            st.dataframe(feat_df, use_container_width=True, hide_index=True)

    elif scan_clicked:
        st.warning("Please enter a URL to scan.")


# ──────────────────────────────────────────────────────────────────────────────
# TAB 2 — Batch Scan
# ──────────────────────────────────────────────────────────────────────────────
with tab_batch:
    st.markdown("### Batch URL Scanner")
    st.markdown("Upload a `.txt` or `.csv` file with one URL per line, or paste URLs below.")

    batch_mode = st.radio("Input method", ["Paste URLs", "Upload file"], horizontal=True)

    urls_to_scan = []

    if batch_mode == "Paste URLs":
        raw = st.text_area("Paste URLs (one per line)", height=150)
        if raw.strip():
            urls_to_scan = [u.strip() for u in raw.strip().splitlines() if u.strip()]
    else:
        uploaded = st.file_uploader("Upload .txt or .csv", type=["txt", "csv"])
        if uploaded:
            content = uploaded.read().decode("utf-8", errors="ignore")
            urls_to_scan = [u.strip() for u in content.splitlines() if u.strip()]

    if urls_to_scan:
        st.info(f"{len(urls_to_scan)} URLs loaded.")

    if st.button("🔍 Scan All", type="primary") and urls_to_scan:
        results = []
        progress = st.progress(0, text="Scanning…")

        for i, url in enumerate(urls_to_scan):
            features   = extract_features(url)
            heur_score = calculate_risk_score(features)
            risk_label = get_risk_label(heur_score)
            sb_result  = check_url_safe_browsing(url)

            final_score = heur_score
            confirmed   = False
            sb_threats  = ""
            if sb_result["checked"] and sb_result["is_malicious"]:
                confirmed   = True
                final_score = max(heur_score, 90)
                risk_label  = "HIGH"
                sb_threats  = ", ".join(sb_result["threats"])

            results.append({
                "URL":               url,
                "Risk Level":        risk_label,
                "Heuristic Score":   heur_score,
                "Final Score":       final_score,
                "GSB Confirmed":     confirmed,
                "GSB Threat Types":  sb_threats,
                "Has HTTPS":         features.get("has_https"),
                "Has IP":            features.get("has_ip"),
                "Subdomains":        features.get("subdomain_count"),
                "Suspicious KW":     ", ".join(features.get("suspicious_keywords", [])),
            })
            progress.progress((i + 1) / len(urls_to_scan), text=f"Scanned {i+1}/{len(urls_to_scan)}")

        progress.empty()
        df = pd.DataFrame(results)

        st.markdown("### Scan Results")

        # Summary metrics
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Total URLs",  len(df))
        mc2.metric("🔴 High",     int((df["Risk Level"] == "HIGH").sum()))
        mc3.metric("🟠 Medium",   int((df["Risk Level"] == "MEDIUM").sum()))
        mc4.metric("🟢 Safe",     int((df["Risk Level"] == "SAFE").sum()))

        st.dataframe(df, use_container_width=True, hide_index=True)

        # Download
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button(
            "⬇️ Download Results (CSV)",
            data=csv_buf.getvalue(),
            file_name="threatlens_results.csv",
            mime="text/csv",
        )
