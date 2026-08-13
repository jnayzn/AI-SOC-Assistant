from app.services.ioc_service import extract_iocs


def test_extract_ips():
    result = extract_iocs("Traffic seen from 185.220.101.4 and 10.0.0.5")
    assert "185.220.101.4" in result.ips
    assert "10.0.0.5" in result.ips


def test_extract_urls_and_domains():
    text = "Click http://paypa1-secure-verify.com/login now"
    result = extract_iocs(text)
    assert any("paypa1-secure-verify.com" in u for u in result.urls)


def test_extract_emails():
    result = extract_iocs("From: IT-Support@paypa1-secure.com to victim@company.com")
    assert "it-support@paypa1-secure.com" in [e.lower() for e in result.emails]
    assert "victim@company.com" in [e.lower() for e in result.emails]


def test_extract_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    result = extract_iocs(f"File hash: {md5}")
    assert md5 in result.hashes


def test_empty_text_returns_empty_result():
    result = extract_iocs("")
    assert result.ips == []
    assert result.urls == []
