"""LangChain client wrapper for the security triage LLM call.

Supports two interchangeable providers (selected via LLM_PROVIDER):
  - "openai": OpenAI's hosted API (requires OPENAI_API_KEY and credits).
  - "ollama": a local Ollama server, reached through its OpenAI-compatible
    endpoint. No API key or internet access to OpenAI is required.

Small local models (e.g. llama3.2:3b) do not always follow "JSON only"
instructions as reliably as hosted frontier models. To make this robust we:
  1. Ask the underlying API for strict JSON output via response_format,
     which both OpenAI and modern Ollama (OpenAI-compatible endpoint)
     support.
  2. If the model still returns text without a parsable JSON object, we
     retry with an explicit correction message a few times before failing.
"""
import json as _json
import logging
import time

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import get_settings
from app.core.exceptions import LLMResponseError
from app.llm.parser import parse_llm_response
from app.llm.prompts import FEW_SHOT_EXAMPLES, SYSTEM_PROMPT, build_user_prompt
from app.schemas.analysis import LLMAnalysisResult

logger = logging.getLogger(__name__)
settings = get_settings()

_JSON_REPAIR_MESSAGE = (
    "Your previous response could not be parsed: it did not contain a single valid JSON object "
    "matching the required schema. Respond again with ONLY the raw JSON object -- no markdown, "
    "no code fences, no prose before or after it."
)

_MAX_PARSE_ATTEMPTS = 3


class TriageLLMClient:
    """Wraps the LLM call with retries, and returns a parsed+validated result."""

    def __init__(self, model: str | None = None, temperature: float | None = None):
        self.provider = settings.LLM_PROVIDER.lower()
        self.temperature = temperature if temperature is not None else settings.OPENAI_TEMPERATURE

        if self.provider == "ollama":
            self.model = model or settings.OLLAMA_MODEL
            self._llm = ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                # Ollama's OpenAI-compatible endpoint ignores the key, but the
                # SDK requires a non-empty string to be set.
                api_key="ollama",
                base_url=settings.OLLAMA_BASE_URL,
                # Modern Ollama versions honor response_format on the
                # OpenAI-compatible route and constrain generation to valid
                # JSON. Older versions silently ignore unknown fields, so
                # this is safe either way and is backed up by the repair
                # retry loop below.
                model_kwargs={"response_format": {"type": "json_object"}},
            )
        else:
            self.model = model or settings.OPENAI_MODEL
            self._llm = ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                api_key=settings.OPENAI_API_KEY,
                model_kwargs={"response_format": {"type": "json_object"}},
            )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def _invoke(self, messages: list) -> str:
        response = self._llm.invoke(messages)
        return response.content if isinstance(response.content, str) else str(response.content)

    def analyze(self, content: str, input_type: str = "unknown") -> tuple[LLMAnalysisResult, float]:
        messages: list = [SystemMessage(content=SYSTEM_PROMPT)]
        # Few-shot examples framed as prior conversation turns for stronger grounding.
        for example in FEW_SHOT_EXAMPLES:
            messages.append(HumanMessage(content=build_user_prompt(example["input"])))
            messages.append(SystemMessage(content=_json.dumps(example["output"])))

        messages.append(HumanMessage(content=build_user_prompt(content, input_type)))

        start = time.perf_counter()
        last_error: LLMResponseError | None = None
        raw_text = ""

        for attempt in range(1, _MAX_PARSE_ATTEMPTS + 1):
            raw_text = self._invoke(messages)
            try:
                result = parse_llm_response(raw_text)
                latency_ms = (time.perf_counter() - start) * 1000
                logger.info(
                    "LLM call completed in %.1fms using provider=%s model=%s (attempt %d/%d)",
                    latency_ms,
                    self.provider,
                    self.model,
                    attempt,
                    _MAX_PARSE_ATTEMPTS,
                )
                return result, latency_ms
            except LLMResponseError as exc:
                last_error = exc
                logger.warning(
                    "Attempt %d/%d: could not parse LLM response as JSON (provider=%s model=%s): %s. "
                    "Raw response (truncated): %r",
                    attempt,
                    _MAX_PARSE_ATTEMPTS,
                    self.provider,
                    self.model,
                    exc.message,
                    raw_text[:500],
                )
                if attempt < _MAX_PARSE_ATTEMPTS:
                    messages.append(AIMessage(content=raw_text))
                    messages.append(HumanMessage(content=_JSON_REPAIR_MESSAGE))

        latency_ms = (time.perf_counter() - start) * 1000
        logger.error(
            "Exhausted %d attempts trying to get valid JSON from provider=%s model=%s",
            _MAX_PARSE_ATTEMPTS,
            self.provider,
            self.model,
        )
        raise last_error or LLMResponseError("No JSON object found in the AI response.")


def get_llm_client() -> TriageLLMClient:
    return TriageLLMClient()
