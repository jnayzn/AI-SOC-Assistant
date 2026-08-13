"""Load and parse the bundled MITRE ATT&CK triage playbooks.

The playbooks are Markdown tables sourced from the community repository
`CodeByHarri/MITRE-ATT_CK-Playbooks` and stored under
`app/data/mitre_playbooks/Playbooks/<Tactic>/T<TTP>_<Name>.md`. They are indexed
by MITRE technique id so the analyzer UI can surface the relevant triage
playbook for every detected technique.

This is read-only reference content — no external calls and no business logic.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

_PLAYBOOK_ROOT = Path(__file__).resolve().parents[1] / "data" / "mitre_playbooks"

# Human labels used in the source Markdown tables -> normalized field keys.
_FIELD_LABELS = {
    "MITRE Tactic": "tactic",
    "MITRE TTP": "ttp",
    "MITRE Sub-TTP": "sub_ttp",
    "Name": "name",
    "Log Sources to Investigate": "log_sources",
    "Key Indicators": "key_indicators",
    "Questions for Analysis": "questions",
    "Decision for Escalation": "escalation",
    "Additional Analysis Steps for L1": "l1_steps",
    "T2 Analyst Actions": "t2_actions",
    "Containment and Further Analysis": "containment",
}

# Fields whose values are numbered / <br>-separated lists in the source.
_LIST_FIELDS = {
    "log_sources",
    "key_indicators",
    "questions",
    "escalation",
    "l1_steps",
    "t2_actions",
    "containment",
}


def _normalize_token(ttp: str) -> str:
    """Uppercase and drop the sub-technique dot: 'T1566.001' -> 'T1566001'."""
    return re.sub(r"[^A-Z0-9]", "", (ttp or "").upper())


def _split_items(value: str) -> list[str]:
    """Turn a numbered / <br>-separated table cell into a clean list of steps."""
    text = value.replace("<br>", "\n")
    # Split on numbered markers like "1. ", "2. " (a trailing space is required
    # so technique ids such as T1548.001 are never split apart).
    parts = re.split(r"(?:^|\n|\s)\d{1,2}\.\s+", text)
    items = [re.sub(r"\s+", " ", p).strip() for p in parts]
    items = [p for p in items if p]
    if items:
        return items
    collapsed = re.sub(r"\s+", " ", text).strip()
    return [collapsed] if collapsed else []


def _parse_markdown(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    fields: dict[str, object] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cell = line.strip("|")
        if "|" not in cell:
            continue
        key, _, value = cell.partition("|")
        key = key.strip()
        value = value.strip()
        if key in ("Column Name", "") or (value and set(value) <= {"-", " "}):
            continue
        field = _FIELD_LABELS.get(key)
        if not field:
            continue
        if field in _LIST_FIELDS:
            fields[field] = _split_items(value)
        else:
            fields[field] = value
    fields["markdown"] = raw
    return fields


@lru_cache(maxsize=1)
def _index() -> dict:
    """Map normalized technique token -> playbook file path."""
    index: dict[str, Path] = {}
    if not _PLAYBOOK_ROOT.exists():
        return index
    for path in sorted(_PLAYBOOK_ROOT.rglob("*.md")):
        token = _normalize_token(path.stem.split("_", 1)[0])
        if token.startswith("T") and token not in index:
            index[token] = path
    return index


def list_playbooks() -> list:
    out: list[dict] = []
    for token, path in sorted(_index().items()):
        data = _parse_markdown(path)
        out.append(
            {
                "ttp": data.get("ttp") or token,
                "name": data.get("name") or path.stem,
                "tactic": data.get("tactic") or path.parent.name.replace("_", " "),
            }
        )
    return out


def get_playbook(ttp: str) -> Optional[dict]:
    token = _normalize_token(ttp)
    if not token:
        return None
    index = _index()
    path = index.get(token)
    if path is None and len(token) > 5:
        # Fall back from a sub-technique to its base technique (T1566001 -> T1566).
        path = index.get(token[:5])
    if path is None:
        return None
    data = _parse_markdown(path)
    data.setdefault("ttp", token)
    data["source_file"] = str(path.relative_to(_PLAYBOOK_ROOT))
    return data
