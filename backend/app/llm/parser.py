"""Parses and validates raw LLM text output into the strict LLMAnalysisResult schema."""
import json
import re

from pydantic import ValidationError

from app.core.exceptions import LLMResponseError
from app.schemas.analysis import LLMAnalysisResult

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json_block(raw_text: str) -> str:
    """Extract the first {...} JSON object from raw LLM text, tolerating
    accidental markdown code fences around the JSON.
    """
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[-1] if "\n" in text else text
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        raise LLMResponseError("No JSON object found in the AI response.")
    return match.group(0)


def parse_llm_response(raw_text: str) -> LLMAnalysisResult:
    json_str = extract_json_block(raw_text)
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise LLMResponseError(f"AI response was not valid JSON: {exc}") from exc

    try:
        return LLMAnalysisResult.model_validate(data)
    except ValidationError as exc:
        raise LLMResponseError(f"AI response failed schema validation: {exc}") from exc
