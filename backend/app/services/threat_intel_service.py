"""Live external threat-intelligence lookups (VirusTotal + Shodan + AbuseIPDB).

Best-effort and non-blocking: if API keys are not configured, or a lookup
fails (network error, timeout, rate limit, invalid key, IOC not found), the
analysis pipeline must still succeed. Failures are recorded as an `error` on
that finding (or the whole enrichment is simply empty when unconfigured)
rather than raised, so a provider outage can never break /analyze.

Lookups run concurrently via a small thread pool since the rest of the
request pipeline (LLM call, DB writes) is synchronous. Successful results
are cached (see ThreatIntelCacheEntry) for THREAT_INTEL_CACHE_TTL_HOURS so
an indicator seen again across analyses does not re-spend API quota. Caching
is itself best-effort: any cache read/write failure (e.g. DB unreachable)
is swallowed and simply falls back to a live lookup.
"""
import base64
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx

from app.core.config import get_settings
from app.schemas.analysis import (
    IOCResult,
    LocalIocFinding,
    RiskLevel,
    ThreatIntelEnrichment,
    ThreatIntelFinding,
    ThreatIntelVerdict,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
# Cap lookups per IOC type so one analysis can't fire an unbounded number of
# outbound requests / burn through API rate limits.
_MAX_PER_TYPE = 3

_VT_BASE = "https://www.virustotal.com/api/v3"
_SHODAN_BASE = "https://api.shodan.io"
_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _error_finding(source: str, indicator: str, indicator_type: str, error: object) -> ThreatIntelFinding:
    logger.warning("%s lookup failed for %s (%s): %s", source, indicator, indicator_type, error)
    return ThreatIntelFinding(
        source=source,
        indicator=indicator,
        indicator_type=indicator_type,
        verdict=ThreatIntelVerdict.UNKNOWN,
        summary="Lookup failed -- see error for details.",
        error=str(error),
        checked_at=_now(),
    )


def _not_found_finding(source: str, indicator: str, indicator_type: str, message: str) -> ThreatIntelFinding:
    return ThreatIntelFinding(
        source=source,
        indicator=indicator,
        indicator_type=indicator_type,
        verdict=ThreatIntelVerdict.UNKNOWN,
        summary=message,
        checked_at=_now(),
    )


def _vt_url_id(url: str) -> str:
    """VirusTotal v3 identifies URLs by base64 (no padding) of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _parse_vt_response(resp: httpx.Response, indicator: str, indicator_type: str) -> ThreatIntelFinding:
    if resp.status_code == 404:
        return _not_found_finding("VirusTotal", indicator, indicator_type, "Not found in VirusTotal.")
    if resp.status_code == 401:
        return _error_finding("VirusTotal", indicator, indicator_type, "Invalid VirusTotal API key.")
    if resp.status_code == 429:
        return _error_finding("VirusTotal", indicator, indicator_type, "VirusTotal rate limit exceeded.")
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return _error_finding("VirusTotal", indicator, indicator_type, exc)

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) if stats else 0

    if malicious > 0:
        verdict = ThreatIntelVerdict.MALICIOUS
    elif suspicious > 0:
        verdict = ThreatIntelVerdict.SUSPICIOUS
    elif total > 0:
        verdict = ThreatIntelVerdict.HARMLESS
    else:
        verdict = ThreatIntelVerdict.UNKNOWN

    if total > 0:
        summary = f"{malicious}/{total} security vendors flagged this {indicator_type} as malicious."
    else:
        summary = "VirusTotal has no vendor analysis data for this indicator yet."

    attributes = data.get("data", {}).get("attributes", {}) or {}
    country = attributes.get("country")
    asn = attributes.get("as_owner") or (
        f"AS{attributes.get('asn')}" if attributes.get("asn") else None
    )
    threat_label = (attributes.get("popular_threat_classification") or {}).get(
        "suggested_threat_label"
    )

    return ThreatIntelFinding(
        source="VirusTotal",
        indicator=indicator,
        indicator_type=indicator_type,
        verdict=verdict,
        summary=summary,
        detail_url=f"https://www.virustotal.com/gui/search/{indicator}",
        malicious_engines=malicious,
        total_engines=total,
        checked_at=_now(),
        country=country,
        asn=asn,
        malware_family=threat_label,
        blacklist_count=malicious + suspicious,
    )


def _lookup_virustotal(
    client: httpx.Client, api_key: str, indicator: str, indicator_type: str
) -> ThreatIntelFinding:
    try:
        if indicator_type == "ip":
            resp = client.get(f"{_VT_BASE}/ip_addresses/{indicator}", headers={"x-apikey": api_key})
        elif indicator_type == "domain":
            resp = client.get(f"{_VT_BASE}/domains/{indicator}", headers={"x-apikey": api_key})
        elif indicator_type == "url":
            resp = client.get(f"{_VT_BASE}/urls/{_vt_url_id(indicator)}", headers={"x-apikey": api_key})
        elif indicator_type == "hash":
            resp = client.get(f"{_VT_BASE}/files/{indicator}", headers={"x-apikey": api_key})
        else:  # pragma: no cover - defensive
            return _error_finding("VirusTotal", indicator, indicator_type, "Unsupported indicator type.")
    except httpx.HTTPError as exc:
        return _error_finding("VirusTotal", indicator, indicator_type, exc)
    return _parse_vt_response(resp, indicator, indicator_type)


def _lookup_shodan_ip(client: httpx.Client, api_key: str, ip: str) -> ThreatIntelFinding:
    try:
        resp = client.get(f"{_SHODAN_BASE}/shodan/host/{ip}", params={"key": api_key})
    except httpx.HTTPError as exc:
        return _error_finding("Shodan", ip, "ip", exc)

    if resp.status_code == 404:
        return _not_found_finding("Shodan", ip, "ip", "No Shodan data for this host.")
    if resp.status_code in (401, 403):
        return _error_finding("Shodan", ip, "ip", "Invalid Shodan API key.")
    if resp.status_code == 429:
        return _error_finding("Shodan", ip, "ip", "Shodan rate limit exceeded.")
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return _error_finding("Shodan", ip, "ip", exc)

    data = resp.json()
    ports = sorted(set(data.get("ports", []) or []))
    org = data.get("org") or "Unknown organization"
    os_name = data.get("os")
    vulns = data.get("vulns", []) or []

    if vulns:
        verdict = ThreatIntelVerdict.SUSPICIOUS
    elif len(ports) > 5:
        verdict = ThreatIntelVerdict.SUSPICIOUS
    else:
        verdict = ThreatIntelVerdict.UNKNOWN

    summary_parts = [f"{len(ports)} open port(s)", org]
    if os_name:
        summary_parts.append(str(os_name))
    if vulns:
        summary_parts.append(f"{len(vulns)} known CVE(s)")
    summary = " - ".join(summary_parts)

    country = data.get("country_name")
    asn = data.get("asn")
    hostnames = data.get("hostnames") or []
    last_update = data.get("last_update")

    return ThreatIntelFinding(
        source="Shodan",
        indicator=ip,
        indicator_type="ip",
        verdict=verdict,
        summary=summary,
        detail_url=f"https://www.shodan.io/host/{ip}",
        checked_at=_now(),
        country=country,
        asn=str(asn) if asn else None,
        reverse_dns=hostnames[0] if hostnames else None,
        last_seen=str(last_update) if last_update else None,
    )


def _lookup_abuseipdb_ip(client: httpx.Client, api_key: str, ip: str) -> ThreatIntelFinding:
    try:
        resp = client.get(
            f"{_ABUSEIPDB_BASE}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        return _error_finding("AbuseIPDB", ip, "ip", exc)

    if resp.status_code in (401, 403):
        return _error_finding("AbuseIPDB", ip, "ip", "Invalid AbuseIPDB API key.")
    if resp.status_code == 429:
        return _error_finding("AbuseIPDB", ip, "ip", "AbuseIPDB rate limit exceeded.")
    if resp.status_code == 422:
        return _error_finding("AbuseIPDB", ip, "ip", "AbuseIPDB rejected this IP address.")
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return _error_finding("AbuseIPDB", ip, "ip", exc)

    data = resp.json().get("data", {}) or {}
    score = int(data.get("abuseConfidenceScore", 0))
    total_reports = int(data.get("totalReports", 0))
    country = data.get("countryCode") or "unknown country"

    if score >= 75:
        verdict = ThreatIntelVerdict.MALICIOUS
    elif score >= 25 or total_reports > 0:
        verdict = ThreatIntelVerdict.SUSPICIOUS
    else:
        verdict = ThreatIntelVerdict.HARMLESS

    summary = f"Abuse confidence {score}/100 from {total_reports} report(s), {country}."
    last_reported = data.get("lastReportedAt")
    isp = data.get("isp")

    return ThreatIntelFinding(
        source="AbuseIPDB",
        indicator=ip,
        indicator_type="ip",
        verdict=verdict,
        summary=summary,
        detail_url=f"https://www.abuseipdb.com/check/{ip}",
        malicious_engines=total_reports,
        checked_at=_now(),
        country=country,
        asn=f"ISP: {isp}" if isp else None,
        blacklist_count=total_reports,
        last_seen=str(last_reported) if last_reported else None,
    )


def _get_cached_finding(source: str, indicator_type: str, indicator: str, ttl_hours: int) -> ThreatIntelFinding | None:
    """Best-effort cache read. Any failure (DB unreachable, table missing on
    a not-yet-migrated deployment, etc.) is swallowed and treated as a
    cache miss so a live lookup is attempted instead."""
    try:
        from app.database.session import SessionLocal
        from app.models.threat_intel_cache import ThreatIntelCacheEntry

        cutoff = _now() - timedelta(hours=ttl_hours)
        with SessionLocal() as session:
            row = (
                session.query(ThreatIntelCacheEntry)
                .filter(
                    ThreatIntelCacheEntry.source == source,
                    ThreatIntelCacheEntry.indicator_type == indicator_type,
                    ThreatIntelCacheEntry.indicator == indicator,
                )
                .first()
            )
            if not row or row.checked_at < cutoff:
                return None
            finding = ThreatIntelFinding.model_validate(row.result)
            finding.from_cache = True
            return finding
    except Exception as exc:  # noqa: BLE001 - cache must never break lookups
        logger.debug("Threat-intel cache read skipped (%s): %s", source, exc)
        return None


def _store_cached_finding(finding: ThreatIntelFinding) -> None:
    """Best-effort cache write. Only successful (non-error) findings are
    cached; failures are never cached so a transient outage or invalid key
    is retried on the next analysis rather than "stuck" for the TTL."""
    if finding.error is not None:
        return
    try:
        from app.database.session import SessionLocal
        from app.models.threat_intel_cache import ThreatIntelCacheEntry

        payload = finding.model_dump(mode="json")
        with SessionLocal() as session:
            row = (
                session.query(ThreatIntelCacheEntry)
                .filter(
                    ThreatIntelCacheEntry.source == finding.source,
                    ThreatIntelCacheEntry.indicator_type == finding.indicator_type,
                    ThreatIntelCacheEntry.indicator == finding.indicator,
                )
                .first()
            )
            if row:
                row.result = payload
                row.checked_at = _now()
            else:
                session.add(
                    ThreatIntelCacheEntry(
                        source=finding.source,
                        indicator_type=finding.indicator_type,
                        indicator=finding.indicator,
                        result=payload,
                    )
                )
            session.commit()
    except Exception as exc:  # noqa: BLE001 - cache must never break lookups
        logger.debug("Threat-intel cache write skipped (%s): %s", finding.source, exc)


import ipaddress

_SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "work", "click", "link", "country", "kim", "party", "review"}
_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
_SUSPICIOUS_URL_KEYWORDS = ("login", "verify", "secure", "account", "update", "confirm", "signin", "password", "banking")
_FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com", "icloud.com"}


def _local_risk(score: int) -> tuple[RiskLevel, int]:
    """Map a 0-100 heuristic score to a (RiskLevel, confidence) pair. Confidence
    reflects how much the purely-lexical heuristic can be trusted (always
    moderate, since this layer never makes network calls)."""
    if score >= 70:
        return RiskLevel.HIGH, 55
    if score >= 40:
        return RiskLevel.MEDIUM, 50
    return RiskLevel.LOW, 45


def _classify_local_ip(ip: str) -> LocalIocFinding:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return LocalIocFinding(indicator=ip, indicator_type="ip", risk_level=RiskLevel.LOW, threat_score=0, confidence=20, notes=["Could not parse this value as an IP address."])
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return LocalIocFinding(indicator=ip, indicator_type="ip", ip_class="private", risk_level=RiskLevel.LOW, threat_score=5, confidence=60, notes=["Private/internal IP address; not externally routable."])
    if addr.is_multicast:
        return LocalIocFinding(indicator=ip, indicator_type="ip", ip_class="multicast", risk_level=RiskLevel.LOW, threat_score=5, confidence=55, notes=["Multicast address."])
    return LocalIocFinding(indicator=ip, indicator_type="ip", ip_class="public", risk_level=RiskLevel.MEDIUM, threat_score=35, confidence=40, notes=["Public routable IP address; cross-check with threat intel sources for reputation."])


def _classify_local_domain(domain: str) -> LocalIocFinding:
    lowered = domain.lower().strip(".")
    tld = lowered.rsplit(".", 1)[-1] if "." in lowered else None
    reasons: list[str] = []
    score = 10
    if tld in _SUSPICIOUS_TLDS:
        reasons.append(f"Uses a commonly abused top-level domain (.{tld}).")
        score += 30
    if lowered.startswith("xn--") or ".xn--" in lowered:
        reasons.append("Contains punycode, a possible sign of homoglyph/IDN spoofing.")
        score += 25
    if lowered.count("-") >= 3:
        reasons.append("Contains many hyphens, a common typosquatting pattern.")
        score += 15
    digit_ratio = sum(ch.isdigit() for ch in lowered) / max(len(lowered), 1)
    if digit_ratio > 0.3:
        reasons.append("High proportion of digits in the domain name.")
        score += 15
    if len(lowered) > 40:
        reasons.append("Unusually long domain name.")
        score += 10
    if not reasons:
        reasons.append("No obvious lexical red flags detected locally.")
    score = min(score, 100)
    risk_level, confidence = _local_risk(score)
    return LocalIocFinding(indicator=domain, indicator_type="domain", tld=tld, risk_level=risk_level, threat_score=score, confidence=confidence, notes=reasons)


def _classify_local_url(url: str) -> LocalIocFinding:
    lowered = url.lower()
    reasons: list[str] = []
    score = 10
    host_match = re.search(r"://([^/]+)", lowered)
    host = host_match.group(1) if host_match else lowered
    host = host.split("@")[-1].split(":")[0]
    try:
        ipaddress.ip_address(host)
        reasons.append("URL host is a raw IP address instead of a domain name.")
        score += 25
    except ValueError:
        pass
    if any(short in host for short in _URL_SHORTENERS):
        reasons.append("Uses a known URL-shortening service, which can mask the real destination.")
        score += 20
    if any(keyword in lowered for keyword in _SUSPICIOUS_URL_KEYWORDS):
        reasons.append("Contains credential-harvesting keywords (login/verify/secure/account).")
        score += 20
    authority = url.split("//")[-1].split("/")[0]
    if "@" in authority:
        reasons.append("Contains an '@' in the authority section, which can obscure the real host.")
        score += 25
    if lowered.count("%") >= 3:
        reasons.append("Heavily URL-encoded, which can hide malicious content.")
        score += 10
    if not reasons:
        reasons.append("No obvious lexical red flags detected locally.")
    score = min(score, 100)
    risk_level, confidence = _local_risk(score)
    return LocalIocFinding(indicator=url, indicator_type="url", risk_level=risk_level, threat_score=score, confidence=confidence, notes=reasons)


def _classify_local_hash(file_hash: str) -> LocalIocFinding:
    length = len(file_hash.strip())
    hash_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(length)
    if hash_type:
        notes = [f"Identified as a likely {hash_type} hash ({length} hex characters); cross-check with threat intel sources."]
    else:
        notes = ["Unrecognized hash length; could not identify the hashing algorithm locally."]
    return LocalIocFinding(indicator=file_hash, indicator_type="hash", hash_algorithm=hash_type, risk_level=RiskLevel.MEDIUM, threat_score=40, confidence=35, notes=notes)


def _classify_local_email(email: str) -> LocalIocFinding:
    lowered = email.lower().strip()
    domain = lowered.rsplit("@", 1)[-1] if "@" in lowered else ""
    local_part = lowered.split("@")[0] if "@" in lowered else lowered
    reasons: list[str] = []
    score = 10
    if domain in _FREE_EMAIL_DOMAINS:
        reasons.append("Sent from a free/consumer webmail domain, common in phishing and BEC.")
        score += 20
    if re.search(r"\d{3,}", local_part):
        reasons.append("Local part contains a long digit sequence, common in auto-generated spoofed addresses.")
        score += 15
    if domain.count("-") >= 2:
        reasons.append("Sender domain contains multiple hyphens, a typosquatting pattern.")
        score += 15
    if not reasons:
        reasons.append("No obvious lexical red flags detected locally.")
    score = min(score, 100)
    risk_level, confidence = _local_risk(score)
    return LocalIocFinding(indicator=email, indicator_type="email", risk_level=risk_level, threat_score=score, confidence=confidence, notes=reasons)


def _compute_local_findings(iocs: IOCResult) -> list[LocalIocFinding]:
    """Zero-dependency, always-available local IOC enrichment. Requires no
    API key and performs no network calls; used as a baseline layer
    alongside VirusTotal/Shodan/AbuseIPDB, always populated when IOCs are
    present regardless of which external providers are configured."""
    findings: list[LocalIocFinding] = []
    for ip in iocs.ips[:_MAX_PER_TYPE]:
        findings.append(_classify_local_ip(ip))
    for domain in iocs.domains[:_MAX_PER_TYPE]:
        findings.append(_classify_local_domain(domain))
    for url in iocs.urls[:_MAX_PER_TYPE]:
        findings.append(_classify_local_url(url))
    for file_hash in iocs.hashes[:_MAX_PER_TYPE]:
        findings.append(_classify_local_hash(file_hash))
    for email in getattr(iocs, "emails", None) or []:
        findings.append(_classify_local_email(email))
    return findings



def enrich_with_threat_intel(
    iocs: IOCResult, client: httpx.Client | None = None, use_cache: bool = True
) -> ThreatIntelEnrichment:
    """Run live VirusTotal/Shodan/AbuseIPDB lookups for the IOCs extracted
    from an analysis. Returns immediately with empty findings if no API key
    is configured. Never raises: individual lookup failures are captured as
    an `error` field on that finding.

    `client` is injectable for tests (e.g. an httpx.Client built with a
    MockTransport) -- when omitted, a real client is created and closed here.
    `use_cache` can be set to False to force fresh lookups (mainly for tests).
    """
    settings = get_settings()
    vt_key = (settings.VIRUSTOTAL_API_KEY or "").strip()
    shodan_key = (settings.SHODAN_API_KEY or "").strip()
    abuseipdb_key = (settings.ABUSEIPDB_API_KEY or "").strip()
    ttl_hours = settings.THREAT_INTEL_CACHE_TTL_HOURS

    enrichment = ThreatIntelEnrichment(
        virustotal_configured=bool(vt_key),
        shodan_configured=bool(shodan_key),
        abuseipdb_configured=bool(abuseipdb_key),
        local_findings=_compute_local_findings(iocs),
    )
    if not vt_key and not shodan_key and not abuseipdb_key:
        return enrichment

    candidates: list[tuple] = []
    if vt_key:
        for ip in iocs.ips[:_MAX_PER_TYPE]:
            candidates.append(("VirusTotal", "ip", ip, _lookup_virustotal, (vt_key, ip, "ip")))
        for domain in iocs.domains[:_MAX_PER_TYPE]:
            candidates.append(("VirusTotal", "domain", domain, _lookup_virustotal, (vt_key, domain, "domain")))
        for url in iocs.urls[:_MAX_PER_TYPE]:
            candidates.append(("VirusTotal", "url", url, _lookup_virustotal, (vt_key, url, "url")))
        for file_hash in iocs.hashes[:_MAX_PER_TYPE]:
            candidates.append(("VirusTotal", "hash", file_hash, _lookup_virustotal, (vt_key, file_hash, "hash")))
    if shodan_key:
        for ip in iocs.ips[:_MAX_PER_TYPE]:
            candidates.append(("Shodan", "ip", ip, _lookup_shodan_ip, (shodan_key, ip)))
    if abuseipdb_key:
        for ip in iocs.ips[:_MAX_PER_TYPE]:
            candidates.append(("AbuseIPDB", "ip", ip, _lookup_abuseipdb_ip, (abuseipdb_key, ip)))

    if not candidates:
        return enrichment

    findings: list[ThreatIntelFinding] = []
    tasks: list[tuple] = []
    for source, indicator_type, indicator, fn, args in candidates:
        cached = _get_cached_finding(source, indicator_type, indicator, ttl_hours) if use_cache else None
        if cached is not None:
            findings.append(cached)
        else:
            tasks.append((fn, args))

    if tasks:
        owns_client = client is None
        active_client = client or httpx.Client(timeout=_TIMEOUT)
        try:
            with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
                futures = [pool.submit(fn, active_client, *args) for fn, args in tasks]
                fresh_findings = [future.result() for future in futures]
        finally:
            if owns_client:
                active_client.close()

        for finding in fresh_findings:
            if use_cache:
                _store_cached_finding(finding)
            findings.append(finding)

    enrichment.findings = findings
    return enrichment
