import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import cast
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import VTCache
from app.services.virustotal_service import AnalysisStats, URLReport


CACHE_TTL = timedelta(hours=24)


class CacheConfigurationError(RuntimeError):
    """Raised when secure cache-key configuration is missing."""


def normalize_url(url: str) -> str:
    """Return the canonical URL used consistently for cache storage and lookup.

    The scheme and host are lowercased, default HTTP(S) ports and fragments are
    removed, an empty path becomes '/', and the path and query remain unchanged.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    host = f"[{hostname}]" if ":" in hostname else hostname

    port = parts.port
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"

    userinfo = ""
    if "@" in parts.netloc:
        userinfo = f"{parts.netloc.rsplit('@', 1)[0]}@"

    return urlunsplit(
        (scheme, f"{userinfo}{host}", parts.path or "/", parts.query, "")
    )


def generate_cache_key(url: str) -> str:
    """Generate a non-reversible HMAC-SHA256 key for a validated URL."""
    secret = settings.CACHE_HASH_SECRET
    if not secret.strip():
        raise CacheConfigurationError("CACHE_HASH_SECRET is not configured")

    normalized_url = normalize_url(url)
    return hmac.new(
        secret.encode("utf-8"),
        normalized_url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def get_cached_url_report(db: Session, url: str) -> URLReport | None:
    """Return a valid cached VirusTotal report, or None on miss or expiry."""
    cache_key = generate_cache_key(url)

    try:
        cached = db.get(VTCache, cache_key)
    except Exception:
        db.rollback()
        raise

    if cached is None or _as_utc(cached.expires_at) <= _utc_now():
        return None

    stats = cast(AnalysisStats, dict(cached.stats))
    return {
        "status": "completed",
        "stats": stats,
        "last_analysis_date": cached.last_analysis_date,
        "error_code": None,
    }


def save_url_report(db: Session, url: str, report: URLReport) -> bool:
    """Upsert a completed VirusTotal report and return whether it was cached."""
    if report["status"] != "completed":
        return False
    if report["stats"] is None:
        raise ValueError("A completed VirusTotal report must include stats")

    cache_key = generate_cache_key(url)
    now = _utc_now()

    try:
        cached = db.get(VTCache, cache_key)
        if cached is None:
            cached = VTCache(
                url_hash=cache_key,
                stats=dict(report["stats"]),
                last_analysis_date=report["last_analysis_date"],
                checked_at=now,
                expires_at=now + CACHE_TTL,
            )
            db.add(cached)
        else:
            cached.stats = dict(report["stats"])
            cached.last_analysis_date = report["last_analysis_date"]
            cached.checked_at = now
            cached.expires_at = now + CACHE_TTL

        db.commit()
    except Exception:
        db.rollback()
        raise

    return True
