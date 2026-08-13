"""API tests for /analyze, /history, /stats using a stubbed LLM client."""
from unittest.mock import patch

from app.schemas.analysis import LLMAnalysisResult

FAKE_RESULT = LLMAnalysisResult(
    classification="Phishing",
    risk_level="High",
    confidence=88,
    summary="Fake phishing summary.",
    explanation="Fake explanation referencing lookalike domain.",
    indicators=["Lookalike domain"],
    mitre_techniques=["T1566 Phishing"],
    recommendations=["Block sender", "Notify SOC"],
)


def _patched_analyze(self, content, input_type="unknown"):
    return FAKE_RESULT, 123.4


@patch("app.llm.client.TriageLLMClient.analyze", new=_patched_analyze)
def test_analyze_endpoint_returns_structured_result(client):
    response = client.post("/api/v1/analyze", json={"content": "Suspicious phishing email body", "input_type": "email"})
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "Phishing"
    assert body["risk_level"] == "High"
    assert body["confidence"] == 88
    assert "id" in body


@patch("app.llm.client.TriageLLMClient.analyze", new=_patched_analyze)
def test_history_lists_created_analysis(client):
    client.post("/api/v1/analyze", json={"content": "Another suspicious email", "input_type": "email"})
    response = client.get("/api/v1/history")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert len(body["items"]) >= 1


@patch("app.llm.client.TriageLLMClient.analyze", new=_patched_analyze)
def test_history_get_and_delete(client):
    create_resp = client.post("/api/v1/analyze", json={"content": "Delete me later", "input_type": "email"})
    analysis_id = create_resp.json()["id"]

    get_resp = client.get(f"/api/v1/history/{analysis_id}")
    assert get_resp.status_code == 200

    delete_resp = client.delete(f"/api/v1/history/{analysis_id}")
    assert delete_resp.status_code == 204

    get_again = client.get(f"/api/v1/history/{analysis_id}")
    assert get_again.status_code == 404


def test_analyze_rejects_empty_content(client):
    response = client.post("/api/v1/analyze", json={"content": ""})
    assert response.status_code == 422


@patch("app.llm.client.TriageLLMClient.analyze", new=_patched_analyze)
def test_stats_endpoint(client):
    client.post("/api/v1/analyze", json={"content": "Yet another phishing sample", "input_type": "email"})
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["total_analyses"] >= 1
