from __future__ import annotations

import re

from app.schemas import EvidenceItem

RULES: list[tuple[str, int, re.Pattern[str], str]] = [
    (
        "urgency",
        18,
        re.compile(
            r"\b(urgent|immediately|act now|within \d+\s*(minutes?|hours?)|"
            r"final notice|account (will be )?locked|funds? (will be )?(seized|frozen)|"
            r"limited time|verify now|last chance|do not ignore)\b",
            re.I,
        ),
        "Urgency language designed to skip independent verification.",
    ),
    (
        "secrecy",
        14,
        re.compile(r"\b(don't tell|do not tell|keep this confidential|do not hang up|stay on the line)\b", re.I),
        "Secrecy or 'do not hang up' coaching is a common social-engineering control tactic.",
    ),
    (
        "credentials",
        28,
        re.compile(
            r"\b(password|passcode|one[-\s]?time code|otp|pin|seed phrase|"
            r"recovery phrase|12[-\s]?word|24[-\s]?word|private key|cvv|ssn|"
            r"social security)\b",
            re.I,
        ),
        "Requests a secret (password, OTP, seed phrase, SSN). Real institutions do not need these by SMS or DM.",
    ),
    (
        "payment_rail",
        16,
        re.compile(
            r"\b(gift card|google play card|steam card|wire transfer|wiring instructions|"
            r"bitcoin|usdt|usdc|western union|moneygram|zelle|cashapp|cash app|venmo)\b",
            re.I,
        ),
        "Asks to move value over a hard-to-reverse rail (wire, gift card, crypto, P2P).",
    ),
    (
        "legal_threat",
        20,
        re.compile(r"\b(arrest|warrant|lawsuit|fbi|ice|deport|seize|legal action|warrant out)\b", re.I),
        "Police or legal-threat framing is typical of government-impersonation scams.",
    ),
    (
        "remote_access",
        22,
        re.compile(r"\b(anydesk|teamviewer|splashtop|remote access|allow me to connect)\b", re.I),
        "Remote-access software request. Support teams at banks do not start this way by text.",
    ),
    (
        "impersonation_name",
        10,
        re.compile(
            r"\b(irs|social security|medicare|amazon|apple support|microsoft support|"
            r"google support|paypal|metamask|coinbase|binance|chase bank|"
            r"bank of america|wells fargo|fraud department|security team)\b",
            re.I,
        ),
        "Names a trusted brand or agency. The name is not proof the sender is that organization.",
    ),
    (
        "new_payment_destination",
        14,
        re.compile(
            r"\b(updated (wiring|banking|account) (details|instructions)|new (account|routing)|"
            r"remit to|send payment (today|now)|hold shipment)\b",
            re.I,
        ),
        "Payment-destination change — classic invoice-redirect fraud.",
    ),
]


def apply_rules(text: str) -> list[EvidenceItem]:
    out: list[EvidenceItem] = []
    for code, weight, pat, detail in RULES:
        if pat.search(text or ""):
            out.append(EvidenceItem(code=code, detail=detail, weight=weight, source="heuristic"))
    return out
