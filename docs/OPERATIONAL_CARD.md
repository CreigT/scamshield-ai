# ScamShield AI Operational Card
**Evidence-backed checker for suspicious texts, emails, invoices, wallet DMs, and URLs**  
Sponsored by CREIGNIFICENT LLC · Status: Deterministic scoring + optional external URL lookups; never navigates suspect pages

## Purpose
Extract indicators from user-supplied content, score deterministic evidence, optionally query Safe Browsing / VirusTotal on the URL string only, and return a verdict (LOW / CAUTION / HIGH / UNKNOWN). Never navigate or execute the suspect resource.

## Trust Boundaries
- The engine never navigates the suspect page or follows links.
- Raw bodies are not stored. Audit records only hash + verdict + evidence codes.
- Optional external lookups (Safe Browsing, VirusTotal) are on the URL string only and require API keys.
- Verdict is evidence-backed scoring, not a guarantee of safety or malice.
- Household identifier is hashed; salt must be set in production.

## Current Enforcement
- POST /api/check and /api/check-upload accept content and return a scored verdict.
- Deterministic indicator extraction and scoring run locally.
- Optional external reputation checks are gated on presence of API keys.
- No automatic link execution or page fetch of the suspect URL.

## Explicit Non-Goals
- Does not browse or render suspect pages.
- Does not store raw user content.
- Does not claim perfect detection or replace human judgment.
- External API results are advisory and rate-limited by the providers.

## Verification Points
1. A check on content containing a URL returns a verdict without the server fetching the URL body.
2. Audit log contains only hash, verdict, and evidence codes (no raw body).
3. Missing external API keys result in local-only scoring (no hard failure).
4. Health endpoint responds without exposing secrets.

## Next Secure Step
Confirm production deployment sets HOUSEHOLD_HASH_SALT and that optional API keys are stored as secrets. Add a short test that asserts no outbound request is made to the user-supplied URL itself.
