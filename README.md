# ThreatLens 🔍

AI-powered malicious URL scanner with lexical heuristics + Google Safe Browsing API.

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Adding Your API Key (IMPORTANT)

Open the file:  **`src/config.py`**

Find this line near the top:

```python
GOOGLE_SAFE_BROWSING_API_KEY = ""   # <-- PASTE YOUR API KEY BETWEEN THE QUOTES
```

Replace the empty string `""` with your key:

```python
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyYourActualKeyHere"
```

Save the file, then run `streamlit run app.py`.

## Getting a Google Safe Browsing API Key

1. Go to https://console.cloud.google.com/
2. Create a project (or select an existing one)
3. Enable **Safe Browsing API**
4. Go to **APIs & Services → Credentials → Create credentials → API Key**
5. Copy the key and paste it into `src/config.py` as shown above.

## Features

- **Heuristic / Lexical Analysis** — always active, no API needed
- **Google Safe Browsing** — real-time threat database check
- **Single URL scan** with detailed risk breakdown
- **Batch scan** via paste or file upload with CSV export
