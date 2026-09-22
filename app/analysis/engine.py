from __future__ import annotations

from app.analysis.actions import actions_for
from app.analysis.heuristics import apply_rules
from app.analysis.indicators import extract
from app.analysis.intel import intel_weight
from app.analysis.urls import analyze_host
from app.injection import scan_injection
from app.schemas import EvidenceItem, IntelResult, Verdict


def decide(score: int, evidence: list[EvidenceItem], indicators: list, unknown_reasons: list[str]) -> Verdict:
    has_url = any(i.kind == "url" for i in indicators)
    has_id = any(i.kind in {"url", "email", "phone", "eth", "btc", "upi"} for i in indicators)
    if score >= 45:
        return "HIGH"
    if score >= 22:
        return "CAUTION"
    if unknown_reasons or not has_id:
        return "UNKNOWN"
    if has_url and any(e.code == "impersonation_name" for e in evidence) and score < 22:
        return "CAUTION"
    return "LOW"


def summarize(verdict: Verdict) -> str:
    return {
        "HIGH": "Multiple independent scam patterns are present. Do not click, pay, or reply from this message.",
        "CAUTION": "Suspicious signals found. Pause and verify through a channel you already trust.",
        "LOW": "No strong scam markers in the submitted text. Unexpected requests still need a second-channel check.",
        "UNKNOWN": "Not enough verified evidence. ScamShield will not invent a confident answer.",
    }[verdict]


def analyze_text(text: str, *, intel: list[IntelResult] | None = None, extra_evidence: list[EvidenceItem] | None = None) -> dict:
    text = text or ""
    indicators = extract(text)
    evidence = apply_rules(text)

    for item in indicators:
        if item.kind == "url":
            evidence.extend(analyze_host(item.value, text))
        if item.kind == "seed_phrase_like":
            evidence.append(EvidenceItem(code="seed_request", detail="Looks like a seed phrase or a request for one. Treat as HIGH.", weight=35, source="heuristic"))
        if item.kind == "email" and item.note:
            domain = item.note
            if any(tok in domain for tok in ("help-", "alerts-", "secure-", "verify-", ".xyz", ".ru")):
                evidence.append(EvidenceItem(code="sender_domain", detail=f"Sender domain is not a typical official mail host: {item.value}", weight=12))

    injection = scan_injection(text)
    if injection:
        evidence.append(EvidenceItem(code="prompt_injection", detail="Payload contains jailbreak-style instructions. Treated as data, not commands.", weight=0, source="policy"))

    intel = intel or []
    for code, weight, detail in intel_weight(intel):
        evidence.append(EvidenceItem(code=code, detail=detail, weight=weight, source="intel"))
    if extra_evidence:
        evidence.extend(extra_evidence)

    seen: set[tuple[str, str]] = set()
    unique: list[EvidenceItem] = []
    for ev in evidence:
        key = (ev.code, ev.detail)
        if key not in seen:
            seen.add(key)
            unique.append(ev)
    evidence = unique

    score = max(0, min(100, sum(max(0, ev.weight) for ev in evidence)))
    unknown_reasons: list[str] = []
    if not text.strip():
        unknown_reasons.append("Empty submission.")
    if len(text.strip()) < 24 and score < 22:
        unknown_reasons.append("Too little context to judge.")
    if not any(i.kind in {"url", "email", "phone", "eth", "btc"} for i in indicators) and score < 22:
        unknown_reasons.append("No checkable identifier (URL, sender, phone, wallet).")

    if unknown_reasons and score < 22:
        for reason in unknown_reasons:
            evidence.append(EvidenceItem(code="insufficient_evidence", detail=reason, weight=0, source="policy"))

    verdict = decide(score, evidence, indicators, unknown_reasons)
    if not text.strip():
        verdict = "UNKNOWN"

    return {
        "verdict": verdict,
        "score": score,
        "summary": summarize(verdict),
        "evidence": evidence,
        "indicators": indicators,
        "actions": actions_for(verdict),
        "intel": intel,
        "injection_hits": injection,
    }
