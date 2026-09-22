from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from app.config import Settings

log = logging.getLogger("scamshield.audit")
_lock = threading.Lock()


def _path(settings: Settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings.data_dir / "audit.jsonl"


def write_event(settings: Settings, event: dict) -> None:
    event = {**event, "ts": datetime.now(timezone.utc).isoformat()}
    line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    with _lock:
        with _path(settings).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def prune(settings: Settings) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retain_days)
    path = _path(settings)
    if not path.exists():
        return
    kept = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                row = json.loads(line)
                ts = datetime.fromisoformat(row.get("ts", "1970-01-01T00:00:00+00:00"))
                if ts >= cutoff:
                    kept.append(line if line.endswith("\n") else line + "\n")
            except Exception:
                continue
    with _lock:
        path.write_text("".join(kept), encoding="utf-8")
