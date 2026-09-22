from __future__ import annotations

import idna
import ipaddress
import re

from app.analysis.indicators import hostname_of
from app.schemas import EvidenceItem

SUSPICIOUS_TLDS = {
    "ru", "cn", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan",
    "zip", "mov", "country", "rest", "fit", "work", "cam", "sbs", "cfd",
    "icu", "cyou", "buzz", "pw",
}

FREE_HOSTS = (
    "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "github.io",
    "gitlab.io", "pages.dev", "webflow.io", "herokuapp.com", "glitch.me",
    "blogspot.com", "wordpress.com", "weebly.com", "square.site",
)

BRAND_DOMAINS = {
    "chase": ["chase.com", "jpmorganchase.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wells fargo": ["wellsfargo.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "amazon": ["amazon.com"],
    "metamask": ["metamask.io"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "irs": ["irs.gov"],
    "ssa": ["ssa.gov", "socialsecurity.gov"],
    "netflix": ["netflix.com"],
}

LOOKALIKE_HOST = [
    (re.compile(r"rnicrosoft|micr0soft|micosoft|soft-secure"), "Microsoft lookalike host"),
    (re.compile(r"paypa[l1]|paypai"), "PayPal lookalike host"),
    (re.compile(r"c0inbase|coinba[s5]e"), "Coinbase lookalike host"),
    (re.compile(r"metarnask|meta-mask-support"), "MetaMask lookalike host"),
    (re.compile(r"app1e"), "Apple lookalike host"),
    (re.compile(r"ch[a4]se-secure|chase-login|chase-alert"), "Chase lookalike host"),
]


def is_private_or_local(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def punycode_flag(host: str) -> str | None:
    if "xn--" in host:
        try:
            return idna.decode(host)
        except Exception:
            return host
    return None


def analyze_host(raw_url: str, full_text: str) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    host = hostname_of(raw_url)
    if not host:
        evidence.append(EvidenceItem(code="url_unparsed", detail="A URL-like string could not be parsed safely.", weight=4))
        return evidence

    if is_private_or_local(host):
        evidence.append(EvidenceItem(code="private_host", detail=f"Host {host} is local or private. ScamShield will not contact it.", weight=8))
        return evidence

    decoded = punycode_flag(host)
    if decoded:
        evidence.append(EvidenceItem(code="punycode", detail=f"Internationalized domain {host} decodes as {decoded}. Lookalike risk.", weight=16))

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        evidence.append(EvidenceItem(code="abused_tld", detail=f"TLD .{tld} on {host} is frequently used in phishing kits.", weight=16))

    if any(host == fh or host.endswith("." + fh) for fh in FREE_HOSTS):
        evidence.append(EvidenceItem(code="free_hosting", detail=f"{host} is free or user hosting. Official bank/wallet login pages are not served from here.", weight=14))

    if host.count("-") >= 2:
        evidence.append(EvidenceItem(code="hyphen_host", detail=f"Hyphenated host pattern: {host}", weight=6))

    for pat, label in LOOKALIKE_HOST:
        if pat.search(host):
            evidence.append(EvidenceItem(code="lookalike_host", detail=f"{label}: {host}", weight=18))

    lower = full_text.lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in lower or any(d.split(".")[0] in lower for d in domains):
            if not any(host == d or host.endswith("." + d) for d in domains):
                if re.search(r"https?://", raw_url, re.I):
                    evidence.append(EvidenceItem(code="brand_host_mismatch", detail=f"Text mentions {brand} but the link host is {host}, not {', '.join(domains)}.", weight=22))
                    break
    return evidence
