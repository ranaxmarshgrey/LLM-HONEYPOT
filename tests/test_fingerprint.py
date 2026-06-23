"""Pytest tests for the fingerprint resistance evaluation suite (Sprint 6).

Runs all 22 fingerprint checks and asserts our system passes at least 18/22.
"""
from __future__ import annotations

import pytest
from tests.fingerprint_tests.fingerprint_checker import FingerprintChecker, CheckResult


class TestFingerprintResistance:
    """Verify the adaptive honeypot passes fingerprint resistance checks."""

    @pytest.fixture(scope="class")
    def checker(self) -> FingerprintChecker:
        """Create a fingerprint checker instance."""
        return FingerprintChecker()

    @pytest.fixture(scope="class")
    def results(self, checker: FingerprintChecker) -> list[CheckResult]:
        """Run all 22 checks once and cache results for the class."""
        return checker.run_all_checks()

    def test_minimum_18_of_22_pass(self, results: list[CheckResult]) -> None:
        """Our system must pass at least 18/22 fingerprint checks."""
        passed = sum(1 for r in results if r.passed)
        failed_names = [r.name for r in results if not r.passed]

        assert passed >= 18, (
            f"Only {passed}/22 checks passed (need ≥18). "
            f"Failed: {failed_names}"
        )

    def test_timing_simple_cmd_passes(self, results: list[CheckResult]) -> None:
        """Response to 'ls' must be under 200ms."""
        result = next(r for r in results if r.name == "timing_simple_cmd")
        assert result.passed, f"timing_simple_cmd failed: {result.actual}"

    def test_cross_ref_passwd_whoami_passes(self, results: list[CheckResult]) -> None:
        """whoami result must appear in /etc/passwd."""
        result = next(r for r in results if r.name == "cross_ref_passwd_whoami")
        assert result.passed, f"cross_ref_passwd_whoami failed: {result.actual}"

    def test_cross_ref_hostname_passes(self, results: list[CheckResult]) -> None:
        """hostname sources must match."""
        result = next(r for r in results if r.name == "cross_ref_hostname")
        assert result.passed, f"cross_ref_hostname failed: {result.actual}"

    def test_pid_realistic_passes(self, results: list[CheckResult]) -> None:
        """PIDs must not be sequential from 1."""
        result = next(r for r in results if r.name == "pid_realistic")
        assert result.passed, f"pid_realistic failed: {result.actual}"

    def test_process_count_realistic_passes(self, results: list[CheckResult]) -> None:
        """ps aux must show more than 3 processes."""
        result = next(r for r in results if r.name == "process_count_realistic")
        assert result.passed, f"process_count_realistic failed: {result.actual}"

    def test_mkdir_cd_works_passes(self, results: list[CheckResult]) -> None:
        """mkdir + cd must work (FakeFS overlay)."""
        result = next(r for r in results if r.name == "mkdir_cd_works")
        assert result.passed, f"mkdir_cd_works failed: {result.actual}"

    def test_write_persists_passes(self, results: list[CheckResult]) -> None:
        """echo > file && cat file must persist."""
        result = next(r for r in results if r.name == "write_persists")
        assert result.passed, f"write_persists failed: {result.actual}"

    def test_no_cowrie_banner_passes(self, results: list[CheckResult]) -> None:
        """No Cowrie signature in env or hostname."""
        result = next(r for r in results if r.name == "no_cowrie_banner")
        assert result.passed, f"no_cowrie_banner failed: {result.actual}"

    def test_env_vars_realistic_passes(self, results: list[CheckResult]) -> None:
        """env must contain USER, PATH, HOME."""
        result = next(r for r in results if r.name == "env_vars_realistic")
        assert result.passed, f"env_vars_realistic failed: {result.actual}"

    def test_history_has_content_passes(self, results: list[CheckResult]) -> None:
        """history must return prior commands."""
        result = next(r for r in results if r.name == "history_has_content")
        assert result.passed, f"history_has_content failed: {result.actual}"

    def test_beats_cowrie_baseline(self, checker: FingerprintChecker, results: list[CheckResult]) -> None:
        """Our system must pass more checks than Cowrie."""
        cowrie_results = checker.run_against_cowrie_baseline()
        our_passed = sum(1 for r in results if r.passed)
        cowrie_passed = sum(1 for r in cowrie_results if r.passed)

        assert our_passed > cowrie_passed, (
            f"Our system ({our_passed}/22) does not beat Cowrie ({cowrie_passed}/22)"
        )

    def test_report_generation(self, checker: FingerprintChecker, results: list[CheckResult]) -> None:
        """Comparison report generates without errors."""
        cowrie_results = checker.run_against_cowrie_baseline()
        text, json_data = checker.generate_comparison_report(results, cowrie_results)

        assert "FINGERPRINT RESISTANCE" in text
        assert json_data["our_system"]["total_checks"] == 22
        assert json_data["cowrie_baseline"]["total_checks"] == 22
