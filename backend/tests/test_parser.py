import pytest

from app.core.exceptions import LLMResponseError
from app.llm.parser import extract_json_block, parse_llm_response

VALID_JSON = """{
  "classification": "Phishing",
  "risk_level": "High",
  "confidence": 90,
  "summary": "A phishing attempt.",
  "explanation": "Lookalike domain and urgency.",
  "indicators": ["Lookalike domain"],
  "mitre_techniques": ["T1566 Phishing"],
  "recommendations": ["Block sender"]
}"""


def test_extract_json_block_plain():
    assert extract_json_block(VALID_JSON).strip().startswith("{")


def test_extract_json_block_with_code_fence():
    fenced = f"```json\n{VALID_JSON}\n```"
    extracted = extract_json_block(fenced)
    assert extracted.strip().startswith("{")


def test_parse_llm_response_valid():
    result = parse_llm_response(VALID_JSON)
    assert result.classification.value == "Phishing"
    assert result.risk_level.value == "High"
    assert result.confidence == 90


def test_parse_llm_response_invalid_json_raises():
    with pytest.raises(LLMResponseError):
        parse_llm_response("not json at all")


def test_parse_llm_response_bad_schema_raises():
    bad = '{"classification": "NotARealLabel", "risk_level": "High", "confidence": 200}'
    with pytest.raises(LLMResponseError):
        parse_llm_response(bad)
