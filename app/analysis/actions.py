from app.schemas import Verdict

COMMON = [
    "ScamShield cannot click the link, send money, reply, or change your accounts. That stays with you.",
]


def actions_for(verdict: Verdict) -> list[str]:
    if verdict == "HIGH":
        return COMMON + [
            "Do not tap the link, scan the QR, or call any number printed in the message.",
            "Do not send money, crypto, gift cards, or one-time codes.",
            "Open the real bank, exchange, or brand app from your home screen or a number on the back of your card.",
            "If you already shared a password or seed phrase, treat the account or wallet as compromised on a clean device.",
            "Report to your provider and to reportfraud.ftc.gov (US) or your local cybercrime portal.",
        ]
    if verdict == "CAUTION":
        return COMMON + [
            "Pause. Verify using a channel you already trust — not the contact details in this message.",
            "For invoices, call a known vendor number from an old statement before sending funds.",
            "Do not install remote-access software because a text told you to.",
        ]
    if verdict == "LOW":
        return COMMON + [
            "No strong scam markers were found. Unexpected requests still deserve a second channel check.",
            "Keep the original message in case the conversation continues.",
        ]
    return COMMON + [
        "Not enough verified evidence for a confident call. That is UNKNOWN, not safe.",
        "Add full sender headers, the raw URL, or the visible text from the screenshot and check again.",
        "Until then, do not click, pay, or share secrets.",
    ]
