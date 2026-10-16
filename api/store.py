"""Firestore features for Shield-AI.

1. Viral scam cache: the same scam is forwarded to thousands of people. Results for
   messages judged SCAM are cached by a SHA-256 fingerprint of the text for 3 days, so
   the next person gets an instant answer and Gemini is not called again.
   SAFE and SUSPICIOUS messages are never stored (they may be personal).

2. Scam radar: anonymous daily counters (no message text) that power the
   "this week in Sri Lanka" panel on the web app.
"""
import asyncio
import hashlib
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from google.cloud import firestore

log = logging.getLogger("shield-ai.store")

PROMPT_VERSION = "v3"          # bump to invalidate the cache after prompt changes
CACHE_TTL = timedelta(days=3)
SL_TZ = timezone(timedelta(hours=5, minutes=30))
CACHE_COL = "scam_cache"
RADAR_COL = "radar_daily"

_db: Optional[firestore.AsyncClient] = None


def db() -> firestore.AsyncClient:
    """Created lazily so the gRPC channel binds to uvicorn's event loop."""
    global _db
    if _db is None:
        _db = firestore.AsyncClient()
    return _db


# ---------- cache ----------
def fingerprint(text: str, reply_language: str) -> str:
    norm = re.sub(r"\s+", " ", text.strip().lower())
    return hashlib.sha256(f"{PROMPT_VERSION}|{reply_language}|{norm}".encode("utf-8")).hexdigest()


async def cache_get(key: str) -> Optional[dict]:
    try:
        snap = await asyncio.wait_for(db().collection(CACHE_COL).document(key).get(), timeout=1.5)
        if not snap.exists:
            return None
        doc = snap.to_dict()
        if doc.get("expires_at") and doc["expires_at"] < datetime.now(timezone.utc):
            return None
        # count the hit, but never let it slow the answer down
        await asyncio.wait_for(
            snap.reference.update({"hits": firestore.Increment(1), "last_hit_at": firestore.SERVER_TIMESTAMP}),
            timeout=1.5,
        )
        doc["hits"] = int(doc.get("hits", 0)) + 1
        return doc
    except Exception:
        log.exception("cache_get failed")
        return None


async def cache_put(key: str, result: dict, model: str) -> None:
    try:
        now = datetime.now(timezone.utc)
        await asyncio.wait_for(
            db().collection(CACHE_COL).document(key).set({
                "result": result,
                "model": model,
                "hits": 1,
                "created_at": now,
                "last_hit_at": now,
                "expires_at": now + CACHE_TTL,   # Firestore TTL policy deletes it after this
            }),
            timeout=2,
        )
    except Exception:
        log.exception("cache_put failed")


# ---------- radar ----------
CATEGORY_RULES = [
    ("otp_pin", ("otp", "pin", "cvv", "password")),
    ("money_reversal", ("reversal", "reload", "ez cash", "ezcash", "mcash", "refund")),
    ("parcel", ("parcel", "courier", "customs", "delivery", "post")),
    ("job", ("job", "task", "part time", "employment")),
    ("prize", ("prize", "lottery", "lucky", "winner", "draw", "gift")),
    ("investment", ("investment", "crypto", "forex", "trading", "double", "pyramid")),
    ("authority", ("police", "cid", "ceb", "water", "government", "authority", "tax", "court")),
    ("marketplace", ("marketplace", "deposit", "rental", "advance", "ikman")),
    ("family_romance", ("romance", "relative", "family", "friend", "son", "daughter")),
    ("bank", ("bank", "card", "account")),
    ("phishing", ("phishing", "link", "login", "verify")),
]


_CATEGORY_RES = [(slug, re.compile(r"\b(" + "|".join(map(re.escape, words)) + r")\b")) for slug, words in CATEGORY_RULES]


def categorize(scam_type: str) -> str:
    s = (scam_type or "").lower()
    for slug, rx in _CATEGORY_RES:
        if rx.search(s):
            return slug
    return "other"


def _today() -> str:
    return datetime.now(SL_TZ).strftime("%Y-%m-%d")


async def radar_record(verdict: str, scam_type: str, language: str, cached: bool) -> None:
    data = {
        "date": _today(),
        "total": firestore.Increment(1),
        f"verdict_{verdict.lower()}": firestore.Increment(1),
        f"lang_{language if language in ('si', 'ta', 'en', 'mixed') else 'other'}": firestore.Increment(1),
    }
    if verdict == "SCAM":
        data[f"cat_{categorize(scam_type)}"] = firestore.Increment(1)
    if cached:
        data["cache_hits"] = firestore.Increment(1)
    try:
        await asyncio.wait_for(db().collection(RADAR_COL).document(_today()).set(data, merge=True), timeout=2)
    except Exception:
        log.exception("radar_record failed")


_radar_cache: dict = {"at": 0.0, "data": None}


async def radar_summary(days: int = 7) -> dict:
    if _radar_cache["data"] is not None and time.time() - _radar_cache["at"] < 30:
        return _radar_cache["data"]
    today = datetime.now(SL_TZ).date()
    refs = [db().collection(RADAR_COL).document((today - timedelta(days=i)).isoformat()) for i in range(days)]
    totals: dict = {}
    async for snap in db().get_all(refs):
        if snap.exists:
            for k, v in snap.to_dict().items():
                if isinstance(v, int):
                    totals[k] = totals.get(k, 0) + v
    cats = sorted(
        ((k[4:], v) for k, v in totals.items() if k.startswith("cat_")),
        key=lambda kv: kv[1], reverse=True,
    )
    out = {
        "days": days,
        "checked": totals.get("total", 0),
        "scams": totals.get("verdict_scam", 0),
        "suspicious": totals.get("verdict_suspicious", 0),
        "safe": totals.get("verdict_safe", 0),
        "cache_hits": totals.get("cache_hits", 0),
        "languages": {k[5:]: v for k, v in totals.items() if k.startswith("lang_")},
        "top_categories": [{"category": k, "count": v} for k, v in cats[:6]],
    }
    _radar_cache.update(at=time.time(), data=out)
    return out
