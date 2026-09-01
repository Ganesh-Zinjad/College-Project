"""
LLM Provider abstraction layer.

Lets Engine 2 (AI Security Auditor) and the Explainable AI feature work with
any of the three supported providers — Anthropic Claude, OpenAI GPT, or
Google Gemini — without changing any of the calling code.

Configuration (backend/.env):
    AI_PROVIDER=anthropic       # Use Claude  (ANTHROPIC_API_KEY required)
    AI_PROVIDER=openai          # Use GPT-4o  (OPENAI_API_KEY required)
    AI_PROVIDER=gemini          # Use Gemini  (GEMINI_API_KEY required)

Install the SDK for whichever provider you use:
    pip install anthropic          # Anthropic
    pip install openai             # OpenAI
    pip install google-genai       # Google Gemini  ← note: NOT google-generativeai
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("secure_code_platform.llm_provider")


# ---------------------------------------------------------------------------
# Base interface
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """
    Minimal interface every provider must implement.
    `complete()` sends a system prompt + user message and returns the
    model's response as a plain string.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name shown in logs / UI."""

    @property
    @abstractmethod
    def model_id(self) -> str:
        """The exact model string sent to the API."""

    @abstractmethod
    def complete(self, system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
        """
        Send a completion request and return the response text.

        Raises:
            RuntimeError: if the API call fails or the SDK is not installed.
        """


# ---------------------------------------------------------------------------
# Anthropic (Claude)
# ---------------------------------------------------------------------------

class AnthropicProvider(LLMProvider):
    """Uses the `anthropic` Python SDK."""

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "Anthropic Claude"

    @property
    def model_id(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "The 'anthropic' package is not installed. "
                "Run: pip install anthropic"
            )

        client = anthropic.Anthropic(api_key=self._api_key)
        response = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return "".join(
            block.text for block in response.content if block.type == "text"
        )


# ---------------------------------------------------------------------------
# OpenAI (GPT-4o / GPT-4 / GPT-3.5-turbo etc.)
# ---------------------------------------------------------------------------

class OpenAIProvider(LLMProvider):
    """Uses the `openai` Python SDK (v1.x)."""

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "OpenAI"

    @property
    def model_id(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError(
                "The 'openai' package is not installed. "
                "Run: pip install openai"
            )

        client = OpenAI(api_key=self._api_key)
        response = client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
        )
        return response.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# Google Gemini  —  uses the NEW `google-genai` SDK (not google-generativeai)
# ---------------------------------------------------------------------------

class GeminiProvider(LLMProvider):
    """
    Uses the new `google-genai` SDK.

    Install:  pip install google-genai
    Docs:     https://googleapis.github.io/python-genai/

    Supported models (as of mid-2026):
        gemini-2.5-pro
        gemini-2.5-flash
        gemini-2.0-flash        ← recommended default
        gemini-1.5-flash        ← still works, older
    """

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "Google Gemini"

    @property
    def model_id(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            raise RuntimeError(
                "The 'google-genai' package is not installed. "
                "Run: pip install google-genai  "
                "(Note: the old 'google-generativeai' package is retired — "
                "uninstall it first with: pip uninstall google-generativeai)"
            )

        client = genai.Client(api_key=self._api_key)

        response = client.models.generate_content(
            model=self._model,
            contents=user_message,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=max_tokens,
                temperature=0.2,   # low temperature → consistent, analytical output
            ),
        )

        # The new SDK exposes response.text directly
        return response.text or ""


# ---------------------------------------------------------------------------
# Factory — reads AI_PROVIDER from settings and returns the right instance
# ---------------------------------------------------------------------------

def get_llm_provider() -> LLMProvider:
    """
    Instantiate and return the configured LLM provider.

    Reads AI_PROVIDER, plus the matching API key and model from settings.
    Raises RuntimeError with a clear message if the provider is unknown or
    the required API key is missing.
    """
    from app.core.config import settings

    provider_name = (settings.AI_PROVIDER or "anthropic").lower().strip()

    if provider_name == "anthropic":
        if not settings.ANTHROPIC_API_KEY:
            raise RuntimeError(
                "AI_PROVIDER is set to 'anthropic' but ANTHROPIC_API_KEY is missing. "
                "Add it to backend/.env"
            )
        logger.info("LLM provider: Anthropic Claude (%s)", settings.AI_AUDIT_MODEL)
        return AnthropicProvider(
            api_key=settings.ANTHROPIC_API_KEY,
            model=settings.AI_AUDIT_MODEL,
        )

    elif provider_name == "openai":
        if not settings.OPENAI_API_KEY:
            raise RuntimeError(
                "AI_PROVIDER is set to 'openai' but OPENAI_API_KEY is missing. "
                "Add it to backend/.env"
            )
        logger.info("LLM provider: OpenAI (%s)", settings.OPENAI_MODEL)
        return OpenAIProvider(
            api_key=settings.OPENAI_API_KEY,
            model=settings.OPENAI_MODEL,
        )

    elif provider_name == "gemini":
        if not settings.GEMINI_API_KEY:
            raise RuntimeError(
                "AI_PROVIDER is set to 'gemini' but GEMINI_API_KEY is missing. "
                "Add it to backend/.env"
            )
        logger.info("LLM provider: Google Gemini (%s)", settings.GEMINI_MODEL)
        return GeminiProvider(
            api_key=settings.GEMINI_API_KEY,
            model=settings.GEMINI_MODEL,
        )

    else:
        raise RuntimeError(
            f"Unknown AI_PROVIDER '{provider_name}'. "
            "Supported values: anthropic | openai | gemini"
        )


def is_any_provider_configured() -> bool:
    """
    Returns True if at least one provider has a valid API key configured.
    Used to decide whether to show the 'AI engine disabled' warning.
    """
    from app.core.config import settings

    provider = (settings.AI_PROVIDER or "anthropic").lower().strip()
    key_map = {
        "anthropic": settings.ANTHROPIC_API_KEY,
        "openai":    settings.OPENAI_API_KEY,
        "gemini":    settings.GEMINI_API_KEY,
    }
    return bool(key_map.get(provider, ""))