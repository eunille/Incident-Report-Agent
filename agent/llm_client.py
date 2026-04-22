# agent/llm_client.py
"""
Thin LLM provider abstraction.

Supported providers (set LLM_PROVIDER in .env):
  groq   — Groq API (llama-3.3-70b-versatile)  FREE
  gemini — Google Gemini 1.5 Flash              FREE
  claude — Anthropic Claude (claude-sonnet-4-5) PAID fallback

Selection priority:
  1. LLM_PROVIDER env var (explicit)
  2. First available API key found (GROQ → GEMINI → ANTHROPIC)
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional


class LLMClient:
    """
    Provider-agnostic LLM client.

    Usage:
        client = LLMClient.from_env()
        text = client.complete(system_prompt, user_message)
    """

    def __init__(self, provider: str, model: str, api_key: str) -> None:
        self._provider = provider
        self._model = model
        self._api_key = api_key
        self._client = self._build_client()
        self._fallback: Optional["LLMClient"] = None

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls, override_provider: Optional[str] = None) -> "LLMClient":
        """
        Construct an LLMClient from environment variables.

        Provider resolution order:
          1. override_provider argument
          2. LLM_PROVIDER env var
          3. First available key: GROQ_API_KEY → GEMINI_API_KEY → ANTHROPIC_API_KEY
        """
        provider = (
            override_provider
            or os.environ.get("LLM_PROVIDER", "").lower()
            or _auto_detect_provider()
        )

        if not provider:
            raise EnvironmentError(
                "No LLM provider configured. Set LLM_PROVIDER and the corresponding "
                "API key (GROQ_API_KEY, GEMINI_API_KEY, or ANTHROPIC_API_KEY) in .env."
            )

        model, api_key = _resolve_model_and_key(provider)
        primary = cls(provider=provider, model=model, api_key=api_key)

        # Wire automatic fallback: groq → gemini → none
        fallback_provider = _get_fallback_provider(provider)
        if fallback_provider:
            try:
                fb_model, fb_key = _resolve_model_and_key(fallback_provider)
                primary._fallback = cls(provider=fallback_provider, model=fb_model, api_key=fb_key)
            except EnvironmentError:
                pass  # Fallback key not available — continue without it

        return primary

    # ── Build underlying client ───────────────────────────────────────────────

    def _build_client(self):  # type: ignore[return]
        if self._provider == "groq":
            from groq import Groq  # type: ignore[import]
            return Groq(api_key=self._api_key)
        if self._provider == "gemini":
            import google.generativeai as genai  # type: ignore[import]
            genai.configure(api_key=self._api_key)
            return genai
        if self._provider == "claude":
            import anthropic
            return anthropic.Anthropic(api_key=self._api_key)
        raise ValueError(f"Unsupported LLM provider: '{self._provider}'")

    # ── Core method ───────────────────────────────────────────────────────────

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 4096,
    ) -> str:
        """
        Send a system + user message and return the assistant text response.

        Raises:
            ValueError: On API or parsing failure.
        """
        try:
            if self._provider == "groq":
                return self._complete_groq(system_prompt, user_message, max_tokens)
            if self._provider == "gemini":
                return self._complete_gemini(system_prompt, user_message, max_tokens)
            if self._provider == "claude":
                return self._complete_claude(system_prompt, user_message, max_tokens)
            raise ValueError(f"Unsupported provider: {self._provider}")
        except Exception as exc:
            if self._fallback and _is_retriable_error(exc):
                return self._fallback.complete(system_prompt, user_message, max_tokens)
            raise

    # ── Provider implementations ──────────────────────────────────────────────

    def _complete_groq(self, system: str, user: str, max_tokens: int) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.1,  # Low temp for structured/factual output
        )
        return response.choices[0].message.content or ""

    def _complete_gemini(self, system: str, user: str, max_tokens: int) -> str:
        model = self._client.GenerativeModel(
            model_name=self._model,
            system_instruction=system,
            generation_config={
                "max_output_tokens": max_tokens,
                "temperature": 0.1,
                "response_mime_type": "application/json",  # structured JSON output
            },
        )
        response = model.generate_content(user)
        return response.text or ""

    def _complete_claude(self, system: str, user: str, max_tokens: int) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text or ""

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def model(self) -> str:
        return self._model

    @property
    def fallback(self) -> Optional["LLMClient"]:
        return self._fallback

    def __repr__(self) -> str:
        fb = f" -> {self._fallback._provider}" if self._fallback else ""
        return f"LLMClient(provider={self._provider!r}, model={self._model!r}{fb})"


# ── Helpers ────────────────────────────────────────────────────────────────────

_PROVIDER_DEFAULTS: dict[str, tuple[str, str]] = {
    "groq":   ("llama-3.3-70b-versatile", "GROQ_API_KEY"),
    "gemini": ("gemini-2.0-flash",        "GEMINI_API_KEY"),
    "claude": ("claude-sonnet-4-5",        "ANTHROPIC_API_KEY"),
}


def _auto_detect_provider() -> Optional[str]:
    """Return the first provider whose API key is set in the environment."""
    for provider, (_, key_name) in _PROVIDER_DEFAULTS.items():
        if os.environ.get(key_name):
            return provider
    return None


_FALLBACK_CHAIN: dict[str, str] = {
    "groq":   "gemini",
    "gemini": "groq",
    "claude": "gemini",
}


def _get_fallback_provider(primary: str) -> Optional[str]:
    """Return the designated fallback provider for the given primary."""
    return _FALLBACK_CHAIN.get(primary)


def _is_retriable_error(exc: Exception) -> bool:
    """Return True if the exception looks like a rate-limit or quota error."""
    msg = str(exc).lower()
    retriable_keywords = (
        "rate limit",
        "rate_limit",
        "too many requests",
        "quota",
        "429",
        "resource_exhausted",
        "tokens per day",
        "daily limit",
    )
    return any(kw in msg for kw in retriable_keywords)


def _resolve_model_and_key(provider: str) -> tuple[str, str]:
    """Return (model_name, api_key) for the given provider."""
    if provider not in _PROVIDER_DEFAULTS:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Valid options: {', '.join(_PROVIDER_DEFAULTS)}"
        )
    default_model, key_name = _PROVIDER_DEFAULTS[provider]

    # Allow model override via env var, e.g. GROQ_MODEL=mixtral-8x7b-32768
    env_model_key = f"{provider.upper()}_MODEL"
    model = os.environ.get(env_model_key, default_model)

    api_key = os.environ.get(key_name, "")
    if not api_key:
        raise EnvironmentError(
            f"Provider '{provider}' requires {key_name} to be set in .env."
        )

    return model, api_key


def strip_json_fences(text: str) -> str:
    """Remove accidental markdown code fences from LLM JSON responses."""
    text = text.strip()
    if text.startswith("```"):
        # Remove opening fence (```json or ```)
        text = re.sub(r"^```(?:json)?\s*\n?", "", text, count=1)
        # Remove closing fence
        text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()
