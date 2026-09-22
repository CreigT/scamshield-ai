from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.schemas import Indicator

URL_RE = re.compile(
    r"\b((?:https?://)?(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?(?:/[^\s]*)?)",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
UPI_RE = re.compile(r"\b[\w.\-]{2,256}@[a-z]{2,64}\b", re.I)
SEED_RE = re.compile(r"\b(?:[a-z]+ ){11,23}[a-z]+\b", re.I)


def _uniq(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def hostname_of(raw: str) -> str | None:
    candidate = raw.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    return host or None


def extract(text: str) -> list[Indicator]:
    text = text or ""
    items: list[Indicator] = []
    for raw in _uniq(URL_RE.findall(text)):
        host = hostname_of(raw)
        items.append(Indicator(kind="url", value=raw[:500], note=host or ""))
    for raw in _uniq(EMAIL_RE.findall(text)):
        items.append(Indicator(kind="email", value=raw[:320], note=raw.split("@")[-1].lower()))
    for raw in _uniq(PHONE_RE.findall(text)):
        items.append(Indicator(kind="phone", value=re.sub(r"\s+", " ", raw)[:32]))
    for raw in _uniq(ETH_RE.findall(text)):
        items.append(Indicator(kind="eth", value=raw))
    for raw in _uniq(BTC_RE.findall(text)):
        items.append(Indicator(kind="btc", value=raw))
    emails = {i.value.lower() for i in items if i.kind == "email"}
    for raw in _uniq(UPI_RE.findall(text)):
        if raw.lower() not in emails and "@" in raw:
            items.append(Indicator(kind="upi", value=raw[:320]))
    if SEED_RE.search(text):
        items.append(Indicator(kind="seed_phrase_like", value="[redacted]", note="possible mnemonic"))
    return items
