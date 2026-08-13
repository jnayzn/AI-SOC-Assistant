"""Offline tests for the VirusTotal/Shodan threat-intel service.

No real network calls are made: httpx.MockTransport simulates VirusTotal and
Shodan HTTP responses so these tests run in fully offline environments.
"""
import httpx
import pytest

from app.core.config import get_settings
from app.schemas.analysis import IOCResult, ThreatIntelVerdict
from app.services.threat_intel_service import enrich_with_threat_intel


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _make_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_returns_empty_when_no_keys_configured(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    iocs = IOCResult(ips=["1.2.3.4"], domains=[], urls=[], emails=[], hashes=[])
    enrichment = enrich_with_threat_intel(iocs, use_cache=False)

    assert enrichment.virustotal_configured is False
    assert enrichment.shodan_configured is False
    assert enrichment.findings == []


def test_virustotal_malicious_ip(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "test-vt-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 12,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 6,
                        }
                    }
                }
            },
        )

    iocs = IOCResult(ips=["185.220.101.4"], domains=[], urls=[], emails=[], hashes=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    assert enrichment.virustotal_configured is True
    assert len(enrichment.findings) == 1
    finding = enrichment.findings[0]
    assert finding.source == "VirusTotal"
    assert finding.verdict == ThreatIntelVerdict.MALICIOUS
    assert finding.malicious_engines == 12
    assert finding.total_engines == 80
    assert finding.error is None


def test_virustotal_harmless_domain(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 2}
                    }
                }
            },
        )

    iocs = IOCResult(ips=[], domains=["example.com"], urls=[], emails=[], hashes=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.HARMLESS
    assert finding.indicator_type == "domain"


def test_virustotal_404_unknown_hash(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    iocs = IOCResult(ips=[], domains=[], urls=[], hashes=["d41d8cd98f00b204e9800998ecf8427e"], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.UNKNOWN
    assert finding.error is None
    assert "not found" in finding.summary.lower()


def test_virustotal_401_invalid_key(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "bad-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})

    iocs = IOCResult(ips=["8.8.8.8"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.UNKNOWN
    assert finding.error is not None
    assert "invalid" in finding.error.lower()


def test_shodan_ip_with_vulns(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan-key")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "test-shodan-key"
        return httpx.Response(
            200,
            json={
                "ports": [22, 80, 443, 8080, 8443, 3389],
                "org": "Example Hosting",
                "os": "Linux",
                "vulns": ["CVE-2021-1234"],
            },
        )

    iocs = IOCResult(ips=["203.0.113.9"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    assert enrichment.shodan_configured is True
    finding = enrichment.findings[0]
    assert finding.source == "Shodan"
    assert finding.verdict == ThreatIntelVerdict.SUSPICIOUS
    assert "CVE" in finding.summary


def test_shodan_404_no_data(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan-key")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "No information available"})

    iocs = IOCResult(ips=["198.51.100.7"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.UNKNOWN
    assert finding.error is None


def test_network_error_is_captured_not_raised(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure")

    iocs = IOCResult(ips=["1.1.1.1"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.UNKNOWN
    assert finding.error is not None


def test_lookups_capped_per_type(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    get_settings.cache_clear()

    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}}}})

    many_ips = [f"10.0.0.{i}" for i in range(10)]
    iocs = IOCResult(ips=many_ips, domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    assert call_count["n"] == 3
    assert len(enrichment.findings) == 3


def test_abuseipdb_malicious_ip(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuseipdb-key")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Key"] == "test-abuseipdb-key"
        assert request.url.params["ipAddress"] == "45.33.32.156"
        return httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 90, "totalReports": 42, "countryCode": "US"}},
        )

    iocs = IOCResult(ips=["45.33.32.156"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    assert enrichment.abuseipdb_configured is True
    finding = enrichment.findings[0]
    assert finding.source == "AbuseIPDB"
    assert finding.verdict == ThreatIntelVerdict.MALICIOUS
    assert finding.malicious_engines == 42
    assert "90/100" in finding.summary


def test_abuseipdb_harmless_ip(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuseipdb-key")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "FR"}},
        )

    iocs = IOCResult(ips=["1.1.1.1"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.verdict == ThreatIntelVerdict.HARMLESS


def test_abuseipdb_invalid_key(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "bad-key")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"errors": [{"detail": "Invalid API key"}]})

    iocs = IOCResult(ips=["2.2.2.2"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler), use_cache=False)

    finding = enrichment.findings[0]
    assert finding.error is not None
    assert "invalid" in finding.error.lower()


def test_abuseipdb_not_configured_by_default(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    get_settings.cache_clear()

    iocs = IOCResult(ips=["3.3.3.3"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, use_cache=False)

    assert enrichment.abuseipdb_configured is False
    assert enrichment.findings == []


def test_cache_reuses_recent_result_without_recalling_api(monkeypatch, tmp_path):
    """Second lookup for the same indicator within the TTL should be served
    from the cache table instead of calling the (mocked) API again."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    get_settings.cache_clear()

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.database.session as session_module
    from app.models.threat_intel_cache import ThreatIntelCacheEntry

    test_engine = create_engine(f"sqlite:///{tmp_path}/threat_intel_cache_test.db")
    ThreatIntelCacheEntry.metadata.create_all(bind=test_engine, tables=[ThreatIntelCacheEntry.__table__])
    TestSessionLocal = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(session_module, "SessionLocal", TestSessionLocal)

    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 10}}}},
        )

    iocs = IOCResult(ips=["9.9.9.9"], domains=[], urls=[], hashes=[], emails=[])

    first = enrich_with_threat_intel(iocs, client=_make_client(handler))
    assert call_count["n"] == 1
    assert first.findings[0].from_cache is False

    second = enrich_with_threat_intel(iocs, client=_make_client(handler))
    assert call_count["n"] == 1  # served from cache, API not called again
    assert second.findings[0].from_cache is True
    assert second.findings[0].verdict == ThreatIntelVerdict.MALICIOUS


def test_cache_does_not_break_lookups_when_db_unreachable(monkeypatch):
    """If the cache DB can't be reached, lookups must still succeed (cache is
    best-effort and must never break the main analysis path)."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("SHODAN_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://nouser:nopass@nonexistent-host-for-tests:5432/nodb")
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 1}}}},
        )

    iocs = IOCResult(ips=["4.4.4.4"], domains=[], urls=[], hashes=[], emails=[])
    enrichment = enrich_with_threat_intel(iocs, client=_make_client(handler))

    assert len(enrichment.findings) == 1
    assert enrichment.findings[0].error is None
