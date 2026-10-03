# Third-Party License Review

Reviewed against the direct dependencies pinned in requirements.txt and requirements-dev.txt.

## Direct runtime dependencies

- fastapi 0.115.6 — permissive (MIT)
- uvicorn 0.34.0 — permissive (BSD-3-Clause)
- pydantic 2.10.4 — permissive (MIT)
- pydantic-settings 2.7.1 — permissive
- python-multipart 0.0.20 — permissive
- httpx 0.28.1 — permissive (BSD-3-Clause)
- idna 3.10 — permissive (BSD-family)
- orjson 3.10.15 — permissive
- gunicorn 23.0.0 — permissive

## Direct development dependencies

- pytest 8.3.4 — permissive
- pytest-asyncio 0.25.0 — permissive

## Repository assets

The audited static UI uses project-owned HTML/CSS/JavaScript and system font stacks. No bundled third-party images, font files, or datasets were found in the repository tree.

## Result

No direct dependency or bundled asset reviewed here presents an obvious conflict with releasing ScamShield AI under Apache-2.0. This is an engineering license review, not legal advice. Transitive dependencies should continue to be checked by automated dependency/SBOM tooling as releases evolve.
