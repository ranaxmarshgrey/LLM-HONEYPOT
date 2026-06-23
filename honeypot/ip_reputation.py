"""IP reputation lookup via AbuseIPDB (Sprint 4).

Called once at session start to enrich the session with threat context.
The result includes an ``initial_score_bonus`` that the Session Manager
adds to the session's starting threat score.

Design constraints:
    - Never blocks session creation -- returns ``unknown()`` on any failure.
    - API key read from ``ABUSEIPDB_API_KEY`` env var.
    - Timeout capped at 3 seconds.
    - Results are cached in-memory for the process lifetime so repeated
      connections from the same IP don't burn API quota.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Optional

import httpx

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_CACHE: Dict[str, "IPReputationResult"] = {}

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT_SECONDS = 3.0


class IPReputationResult(BaseModel):
    """Structured result from an AbuseIPDB lookup."""

    ip: str
    abuse_confidence_score: int = Field(ge=0, le=100, default=0)
    is_tor: bool = False
    is_vpn: bool = False
    country_code: str = "XX"
    isp: str = "Unknown"
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    initial_score_bonus: int = Field(ge=0, default=0)

    @classmethod
    def unknown(cls, ip: str) -> IPReputationResult:
        """Safe fallback when the API is unavailable or key is missing."""
        return cls(ip=ip)


def _compute_bonus(
    abuse_confidence: int,
    is_tor: bool,
    total_reports: int,
) -> int:
    """Derive an initial threat-score bonus from reputation data.

    Scoring rules:
        abuse_confidence >= 80  -> +20  (known malicious)
        abuse_confidence >= 50  -> +10  (suspicious)
        abuse_confidence >= 25  -> +5   (reported)
        is_tor                  -> +15  (anonymisation layer)
        total_reports >= 100    -> +8   (heavily reported)
    """
    bonus = 0
    if abuse_confidence >= 80:
        bonus += 20
    elif abuse_confidence >= 50:
        bonus += 10
    elif abuse_confidence >= 25:
        bonus += 5

    if is_tor:
        bonus += 15

    if total_reports >= 100:
        bonus += 8

    return bonus


async def check_ip_reputation(ip: str) -> IPReputationResult:
    """Query AbuseIPDB for *ip* and return structured reputation data.

    Always returns a result -- never raises. On any failure (missing key,
    network error, bad JSON, timeout) returns ``IPReputationResult.unknown(ip)``.

    Results are cached: the first call for a given IP hits the API, all
    subsequent calls return the cached value instantly.

    Args:
        ip: The IPv4/IPv6 address to look up.

    Returns:
        An ``IPReputationResult`` with ``initial_score_bonus`` populated.
    """
    if ip in _CACHE:
        return _CACHE[ip]

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.debug("ABUSEIPDB_API_KEY not set -- skipping IP reputation check")
        result = IPReputationResult.unknown(ip)
        _CACHE[ip] = result
        return result

    # Private / loopback IPs -- don't waste an API call
    if _is_private(ip):
        result = IPReputationResult.unknown(ip)
        _CACHE[ip] = result
        return result

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                _API_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                    "verbose": "",
                },
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

        abuse_score = int(data.get("abuseConfidenceScore", 0))
        is_tor = bool(data.get("isTor", False))
        total_reports = int(data.get("totalReports", 0))

        result = IPReputationResult(
            ip=ip,
            abuse_confidence_score=abuse_score,
            is_tor=is_tor,
            is_vpn=False,
            country_code=data.get("countryCode", "XX") or "XX",
            isp=data.get("isp", "Unknown") or "Unknown",
            total_reports=total_reports,
            last_reported_at=data.get("lastReportedAt"),
            initial_score_bonus=_compute_bonus(abuse_score, is_tor, total_reports),
        )

    except Exception as exc:
        logger.warning("IP reputation check failed for %s: %s", ip, exc)
        result = IPReputationResult.unknown(ip)

    _CACHE[ip] = result
    return result


def clear_cache() -> None:
    """Clear the in-memory reputation cache (useful in tests)."""
    _CACHE.clear()


def _is_private(ip: str) -> bool:
    """Quick check for RFC-1918 / loopback / link-local addresses."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
