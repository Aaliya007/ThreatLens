# ThreatLens 🔍
AI-powered malicious URL scanner with lexical heuristics + Google Safe Browsing API.
<img width="1600" height="818" alt="image" src="https://github.com/user-attachments/assets/84e21fc3-e1f1-4ed1-a7fd-59ac0795d6b6" />

## Project Structure

```text
## Project Structure

```text
threatlens/
├── app.py              ← Main Streamlit app
├── requirements.txt
├── README.md
├── .streamlit/
│   └── config.toml     
└── src/
    ├── config.py       
    ├── safe_browsing.py
    └── url_features.py ← Lexical/heuristic checks
```

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Adding Your API Key 

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

## Future Improvements

- Add live threat-intelligence API integration for URL, domain, IP, and file reputation checks.
- Introduce user authentication and role-based access for analyst and admin workflows.
- Store scan history in a database for audit trails and trend analysis.
- Add export options for PDF, CSV, and JSON reports.
- Include batch scanning for multiple URLs or indicators at once.
- Improve explainability by showing why a threat score was assigned.
- Add visual analytics such as detection trends, category breakdowns, and historical risk summaries.
- Support `.env` configuration for API keys and deployment settings.
- Package the project with Docker for easier deployment.
- Add unit tests and integration tests for more reliable releases.

## Notes

- Keep secrets such as API keys out of source code and store them in environment variables.
- Use a virtual environment to avoid package conflicts.
- Update `requirements.txt` whenever you add a new dependency.

