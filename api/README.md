# Shield-AI (API + web app)

Scam message analysis for Sri Lanka, built on Google Cloud.

## Pipeline
* Extract links from the message
* Check each link with **Google Web Risk API** (parallel, hard signal)
* Analyse the message with **Gemini on Vertex AI** using a strict JSON schema
* Merge: a Web Risk hit always forces `SCAM` (risk 95+)
* Served from **Cloud Run** (asia-southeast1)

## Web app
Served from the same Cloud Run service at `/` (`static/index.html`). UI in Sinhala, Tamil and English.

## Run locally
```bash
gcloud auth application-default login
pip install -r requirements.txt
export GOOGLE_CLOUD_PROJECT=your-project-id
uvicorn main:app --reload --port 8080
./test.sh
```

## Deploy
```bash
PROJECT_ID=your-project-id ./setup.sh
API_URL=https://<your-cloud-run-url> ./test.sh
```

## API
`POST /analyze`
```json
{ "text": "message here", "reply_language": "auto" }
```
`reply_language`: `auto`, `si`, `ta`, `en`

Response fields: `verdict` (SAFE, SUSPICIOUS, SCAM), `risk_score`, `scam_type`,
`detected_language`, `red_flags`, `explanation`, `recommended_actions`,
`url_checks`, `model`, `latency_ms`.

## Config (env vars)
* `MODEL_ID` (default `gemini-2.5-flash-lite`)
* `GEMINI_LOCATION` (default `global`)
* `CORS_ORIGINS` (default `*`, lock down after the web UI is deployed)
