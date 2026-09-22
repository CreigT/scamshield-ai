# ScamShield AI

Evidence-backed checker for suspicious texts, emails, invoices, wallet DMs, and URLs.

The engine extracts indicators, scores deterministic evidence, optionally asks Safe Browsing / VirusTotal about the URL string, and returns LOW / CAUTION / HIGH / UNKNOWN. It never navigates the suspect page.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
pytest -q
uvicorn app.main:app --reload --port 8080
```

Open http://127.0.0.1:8080

## Docker

```bash
docker compose up --build
```

## Deploy

Render: use `render.yaml` as a Blueprint. Set `HOUSEHOLD_HASH_SALT`. Optional `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY`.

Fly.io:

```bash
fly launch --no-deploy
fly secrets set HOUSEHOLD_HASH_SALT="$(openssl rand -hex 32)"
fly deploy
```

Any 12-factor host:

```
uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers
```

## API

`POST /api/check` with `{ "content", "source_hint", "household_id" }`

`POST /api/check-upload` multipart file

`GET /health`

Raw bodies are not stored. Audit writes hash + verdict + evidence codes only.

Apache-2.0
