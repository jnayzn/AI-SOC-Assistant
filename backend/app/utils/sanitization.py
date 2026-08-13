"""Input sanitization and prompt-injection / jailbreak heuristic detection.

Defense-in-depth note: the primary defense against prompt injection is
treating all submitted content as untrusted DATA in app/llm/prompts.py
(the system prompt explicitly instructs the model to ignore embedded
instructions). This module adds a lightweight heuristic pre-filter and
input hygiene layer on top of that.
"""
import html
import re

from app.core.exceptions import PromptInjectionDetected

MAX_CONTENT_LENGTH = 20000

_INJECTION_PATTERNS = [
    r"ignore (all|any|previous|prior|above) instructions",
    r"disregard (all|any|previous|prior|above) instructions",
    r"you are now (a|an|in) (?!.{0,40}(analysis|classification))",
    r"system prompt\s*[:=]",
    r"reveal (your|the) (system prompt|instructions|prompt)",
    r"act as (?:a\s+)?(?:jailbroken|unfiltered|dan)\b",
    r"\bdo anything now\b",
    r"pretend (you are|to be) (?!.{0,40}(analysis|classification))",
    r"override (your|the) (guardrails|safety|rules)",
    r"</?system>",
    r"</?\s*instructions\s*>",
]

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_input(text: str) -> str:
    """Strips control characters and unescapes HTML entities without altering
    the semantic content the analyst needs to see (we do NOT strip suspicious
    URLs/keywords -- those are exactly what the analyst needs classified).
    """
    text = text[:MAX_CONTENT_LENGTH]
    text = _CONTROL_CHAR_RE.sub("", text)
    text = html.unescape(text)
    return text.strip()


def detect_prompt_injection(text: str) -> list[str]:
    """Returns the list of matched heuristic patterns (empty if none)."""
    matches = []
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(text):
            matches.append(pattern.pattern)
    return matches


def guard_against_injection(text: str, *, block: bool = False) -> list[str]:
    """Detects heuristic prompt-injection attempts.

    By default (block=False) this only flags matches so the content can still
    be analyzed (a phishing email that says "ignore previous instructions" is
    itself a legitimate, interesting sample to classify as suspicious/phishing).
    Set block=True for stricter deployments that should hard-reject such input.
    """
    matches = detect_prompt_injection(text)
    if matches and block:
        raise PromptInjectionDetected(
            "Submitted content contains suspected prompt-injection instructions and was rejected."
        )
    return matches
