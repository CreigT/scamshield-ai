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

## SECURE

- The service never navigates or fetches the body of a user-supplied suspect URL.
- Raw content is not stored. Audit records only hash, verdict, and evidence codes.
- Optional external reputation lookups operate on the URL string only and require configured API keys.
- Household identifier is hashed; production requires a strong HOUSEHOLD_HASH_SALT.

## VERIFY

Verification is evidence that the no-navigation and no-raw-storage boundaries hold.

- A check returns a verdict without the server requesting the user-supplied URL.
- Audit output contains no raw body.
- Absence of external API keys does not cause hard failure (local scoring continues).

See `docs/VERIFY_WALKTHROUGH.md` for the concrete steps. Full operational card: `docs/OPERATIONAL_CARD.md`.

## DOCUMENT

- Operational card: `docs/OPERATIONAL_CARD.md`
- Verification walkthrough: `docs/VERIFY_WALKTHROUGH.md`
- Documentation defines the no-navigation and audit boundaries; code implements the checker.

Apache-2.0
