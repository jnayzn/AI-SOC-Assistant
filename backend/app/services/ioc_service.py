"""Regex-based Indicator of Compromise (IOC) extraction service."""
import re

from app.schemas.analysis import IOCResult

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\)\]\}\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def extract_iocs(text: str) -> IOCResult:
    ips = sorted(set(_IP_RE.findall(text)))
    urls = sorted(set(_URL_RE.findall(text)))
    emails = sorted(set(_EMAIL_RE.findall(text)))
    hashes = sorted(set(_HASH_RE.findall(text)))

    domains = set(_DOMAIN_RE.findall(text))
    # Remove domains that are actually part of an email address or URL to avoid duplication noise.
    email_domains = {e.split("@")[-1] for e in emails}
    domains = {d for d in domains if d not in email_domains}
    domains -= set(ips)

    return IOCResult(
        ips=ips,
        domains=sorted(domains),
        urls=urls,
        emails=emails,
        hashes=hashes,
    )
