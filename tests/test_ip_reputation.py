"""Tests for IP reputation module -- Sprint 4.

All tests use mocked HTTP responses (no real API calls).
Covers:
    - Successful lookups with various abuse scores
    - Bonus score computation at each threshold
    - Tor exit node detection
    - High-report-count bonus
    - API key missing -> graceful fallback
    - Network error -> graceful fallback
    - Timeout -> graceful fallback
    - Malformed JSON -> graceful fallback
    - HTTP error status -> graceful fallback
    - Private/loopback IPs -> skip API call
    - Caching (second call returns cached value)
    - Cache clearing
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from honeypot.ip_reputation import (
    IPReputationResult,
    _compute_bonus,
    _is_private,
    check_ip_reputation,
    clear_cache,
)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def _clear_cache():
    """Ensure each test starts with a clean cache."""
    clear_cache()
    yield
    clear_cache()


# ===================================================================
# Bonus computation unit tests
# ===================================================================

class TestComputeBonus:

    def test_zero_abuse_score(self):
        assert _compute_bonus(0, is_tor=False, total_reports=0) == 0

    def test_low_abuse_score(self):
        assert _compute_bonus(10, is_tor=False, total_reports=0) == 0

    def test_abuse_25_threshold(self):
        assert _compute_bonus(25, is_tor=False, total_reports=0) == 5

    def test_abuse_49(self):
        assert _compute_bonus(49, is_tor=False, total_reports=0) == 5

    def test_abuse_50_threshold(self):
        assert _compute_bonus(50, is_tor=False, total_reports=0) == 10

    def test_abuse_79(self):
        assert _compute_bonus(79, is_tor=False, total_reports=0) == 10

    def test_abuse_80_threshold(self):
        assert _compute_bonus(80, is_tor=False, total_reports=0) == 20

    def test_abuse_100(self):
        assert _compute_bonus(100, is_tor=False, total_reports=0) == 20

    def test_tor_bonus(self):
        assert _compute_bonus(0, is_tor=True, total_reports=0) == 15

    def test_high_reports_bonus(self):
        assert _compute_bonus(0, is_tor=False, total_reports=100) == 8

    def test_high_reports_99_no_bonus(self):
        assert _compute_bonus(0, is_tor=False, total_reports=99) == 0

    def test_all_bonuses_stack(self):
        # abuse 80 (20) + tor (15) + reports 100 (8) = 43
        assert _compute_bonus(80, is_tor=True, total_reports=200) == 43

    def test_abuse_50_plus_tor(self):
        # abuse 50 (10) + tor (15) = 25
        assert _compute_bonus(50, is_tor=True, total_reports=0) == 25


# ===================================================================
# IPReputationResult model
# ===================================================================

class TestIPReputationResult:

    def test_unknown_defaults(self):
        r = IPReputationResult.unknown("1.2.3.4")
        assert r.ip == "1.2.3.4"
        assert r.abuse_confidence_score == 0
        assert r.is_tor is False
        assert r.initial_score_bonus == 0
        assert r.country_code == "XX"
        assert r.isp == "Unknown"

    def test_fields_populated(self):
        r = IPReputationResult(
            ip="5.6.7.8",
            abuse_confidence_score=85,
            is_tor=True,
            country_code="RU",
            isp="Evil ISP",
            total_reports=150,
            last_reported_at="2026-04-01T00:00:00Z",
            initial_score_bonus=43,
        )
        assert r.abuse_confidence_score == 85
        assert r.initial_score_bonus == 43


# ===================================================================
# Private IP detection
# ===================================================================

class TestIsPrivate:

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.0.100",
        "127.0.0.1",
        "127.0.0.2",
        "0.0.0.0",
    ])
    def test_private_ips(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "45.33.32.156",
        "172.32.0.1",
    ])
    def test_public_ips(self, ip):
        assert _is_private(ip) is False

    def test_invalid_ip_returns_false(self):
        assert _is_private("not-an-ip") is False


# ===================================================================
# check_ip_reputation -- mocked HTTP
# ===================================================================

def _make_mock_response(data: dict, status_code: int = 200):
    """Build a mock httpx.Response-like object."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"data": data}
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


def _mock_client(response):
    """Create a mock httpx.AsyncClient context manager."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TestCheckIPReputation:

    def test_known_malicious_ip(self):
        data = {
            "abuseConfidenceScore": 95,
            "isTor": False,
            "countryCode": "CN",
            "isp": "Bad Hosting Co",
            "totalReports": 250,
            "lastReportedAt": "2026-04-20T12:00:00Z",
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key-123"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("45.33.32.156"))

        assert result.ip == "45.33.32.156"
        assert result.abuse_confidence_score == 95
        assert result.country_code == "CN"
        assert result.isp == "Bad Hosting Co"
        assert result.total_reports == 250
        assert result.initial_score_bonus == 20 + 8  # abuse>=80(20) + reports>=100(8)

    def test_tor_exit_node(self):
        data = {
            "abuseConfidenceScore": 30,
            "isTor": True,
            "countryCode": "DE",
            "isp": "Tor Exit",
            "totalReports": 50,
            "lastReportedAt": "2026-04-19T00:00:00Z",
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("185.220.100.1"))

        assert result.is_tor is True
        assert result.initial_score_bonus == 5 + 15  # abuse>=25(5) + tor(15)

    def test_clean_ip(self):
        data = {
            "abuseConfidenceScore": 0,
            "isTor": False,
            "countryCode": "US",
            "isp": "Cloudflare",
            "totalReports": 0,
            "lastReportedAt": None,
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("1.1.1.1"))

        assert result.abuse_confidence_score == 0
        assert result.initial_score_bonus == 0

    def test_moderate_suspicion(self):
        data = {
            "abuseConfidenceScore": 55,
            "isTor": False,
            "countryCode": "BR",
            "isp": "Some ISP",
            "totalReports": 30,
            "lastReportedAt": "2026-03-01T00:00:00Z",
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("200.100.50.25"))

        assert result.initial_score_bonus == 10  # abuse>=50(10)

    # --- Failure modes: graceful fallback ---

    def test_no_api_key_returns_unknown(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            result = _run(check_ip_reputation("8.8.8.8"))

        assert result.ip == "8.8.8.8"
        assert result.abuse_confidence_score == 0
        assert result.initial_score_bonus == 0

    def test_network_error_returns_unknown(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=ConnectionError("network down"))
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=ctx):
                result = _run(check_ip_reputation("8.8.4.4"))

        assert result.ip == "8.8.4.4"
        assert result.initial_score_bonus == 0

    def test_timeout_returns_unknown(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=TimeoutError("timed out"))
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=ctx):
                result = _run(check_ip_reputation("9.9.9.9"))

        assert result.ip == "9.9.9.9"
        assert result.initial_score_bonus == 0

    def test_http_500_returns_unknown(self):
        mock_resp = _make_mock_response({}, status_code=500)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("5.5.5.5"))

        assert result.initial_score_bonus == 0

    def test_http_429_rate_limit_returns_unknown(self):
        mock_resp = _make_mock_response({}, status_code=429)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("6.6.6.6"))

        assert result.initial_score_bonus == 0

    def test_malformed_json_returns_unknown(self):
        mock_client_inner = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("bad json")
        mock_client_inner.get = AsyncMock(return_value=mock_resp)
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_client_inner)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=ctx):
                result = _run(check_ip_reputation("7.7.7.7"))

        assert result.initial_score_bonus == 0

    # --- Private IPs skip API call ---

    def test_private_ip_skips_api(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient") as mock_cls:
                result = _run(check_ip_reputation("192.168.1.100"))
                mock_cls.assert_not_called()

        assert result.ip == "192.168.1.100"
        assert result.initial_score_bonus == 0

    def test_loopback_skips_api(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient") as mock_cls:
                result = _run(check_ip_reputation("127.0.0.1"))
                mock_cls.assert_not_called()

        assert result.initial_score_bonus == 0

    # --- Caching ---

    def test_cache_returns_same_result(self):
        data = {
            "abuseConfidenceScore": 60,
            "isTor": False,
            "countryCode": "RU",
            "isp": "Test ISP",
            "totalReports": 10,
            "lastReportedAt": None,
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                r1 = _run(check_ip_reputation("33.33.33.33"))

            # Second call should use cache, not hit the API
            with patch("honeypot.ip_reputation.httpx.AsyncClient") as mock_cls:
                r2 = _run(check_ip_reputation("33.33.33.33"))
                mock_cls.assert_not_called()

        assert r1.ip == r2.ip
        assert r1.abuse_confidence_score == r2.abuse_confidence_score
        assert r1.initial_score_bonus == r2.initial_score_bonus

    def test_cache_clear(self):
        data = {
            "abuseConfidenceScore": 60,
            "isTor": False,
            "countryCode": "RU",
            "isp": "Test",
            "totalReports": 5,
        }
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                _run(check_ip_reputation("44.44.44.44"))

        clear_cache()

        # After clearing, a new call for the same IP should try the API again
        mock_resp2 = _make_mock_response(data)
        mock_client2 = _mock_client(mock_resp2)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client2) as mock_cls:
                _run(check_ip_reputation("44.44.44.44"))
                mock_cls.assert_called()

    # --- Missing data fields handled gracefully ---

    def test_missing_fields_in_response(self):
        data = {"abuseConfidenceScore": 42}
        mock_resp = _make_mock_response(data)
        mock_client = _mock_client(mock_resp)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=mock_client):
                result = _run(check_ip_reputation("55.55.55.55"))

        assert result.abuse_confidence_score == 42
        assert result.country_code == "XX"
        assert result.isp == "Unknown"
        assert result.is_tor is False

    def test_empty_data_in_response(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"data": {}}
        mock_client = _mock_client(mock_resp)

        # Override the get to return our specific mock
        inner = AsyncMock()
        inner.get = AsyncMock(return_value=mock_resp)
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=inner)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("honeypot.ip_reputation.httpx.AsyncClient", return_value=ctx):
                result = _run(check_ip_reputation("66.66.66.66"))

        assert result.ip == "66.66.66.66"
        assert result.initial_score_bonus == 0
