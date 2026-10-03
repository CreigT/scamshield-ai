# Security Policy

## Reporting
Please do not disclose exploitable vulnerabilities in a public issue. Use GitHub private vulnerability reporting when available or contact the maintainer privately.

## Baseline
- Never commit credentials, API keys, tokens, secrets, or customer data.
- Validate untrusted inputs and model/tool outputs.
- Separate authentication from authorization where either is introduced.
- Use least-privilege permissions for external services.
- Keep raw suspicious content out of persistent audit records.
- Do not automatically navigate submitted URLs.
- Log security-relevant actions without logging secrets.
- Review and lock dependencies.

## AI and URL-analysis risks
Consider prompt injection, malicious URLs, excessive agency, data leakage, insecure tool invocation, unsafe output handling, SSRF-like behavior, and abuse of third-party intelligence APIs.

## Production configuration
Replace development placeholder salts and secrets. Do not deploy with the default household hash salt.
