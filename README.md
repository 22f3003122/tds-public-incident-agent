# TDS Public HTTPS Incident Agent

FastAPI implementation for the `ga5-incident-agent/v2` assignment.

## Files
- `main.py` — incident API, persistent state machine, receipt handling and OTLP trace
- `requirements.txt` — Python dependencies
- `render.yaml` — Render deployment configuration
- `config.env.example` — AI Pipe environment variable template
- `.gitignore` — excludes secrets, virtual environments and SQLite state

## AI Pipe configuration
Copy `config.env.example` to `config.env`, then replace the placeholder with your AI Pipe token:

```env
OPENAI_API_KEY=YOUR_AIPIPE_TOKEN
OPENAI_BASE_URL=https://aipipe.org/openai/v1
OPENAI_MODEL=gpt-5-nano
```

The application calls the OpenAI-compatible `/chat/completions` endpoint. The token is read only by the server and is never included in incident prompts, API responses, action logs or telemetry.

## Local setup (Ubuntu)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.env.example config.env
nano config.env
uvicorn main:app --host 0.0.0.0 --port 8000
```

Check health:
```bash
curl http://127.0.0.1:8000/health
```

## Required API
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

## GitHub
Do not commit `config.env`, `.env`, `incident_agent.db`, or your virtual environment.
