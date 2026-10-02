"""NEXUS AI provider abstraction.

Supports interchangeable OpenAI-compatible providers:
- Groq cloud API
- Google Gemini API (OpenAI-compatible endpoint)
- Ollama local API

The agents and workflow do not need to know which provider is active.
"""
from __future__ import annotations

import os
from typing import Any

from crewai import LLM


PROVIDERS = ("groq", "gemini", "ollama")


def _value(config: dict[str, str], key: str, env: str, default: str = "") -> str:
    return str(config.get(key) or os.getenv(env) or default).strip()


def provider_settings(config: dict[str, str] | None = None) -> dict[str, str]:
    config = config or {}
    provider = _value(config, "provider", "AI_PROVIDER", "groq").lower()

    if provider == "gemini":
        return {
            "provider": "gemini",
            "api_key": _value(config, "api_key", "GEMINI_API_KEY"),
            "model": _value(config, "model", "GEMINI_MODEL", "gemini-3.1-flash-lite"),
            "base_url": _value(
                config,
                "base_url",
                "GEMINI_BASE_URL",
                "https://generativelanguage.googleapis.com/v1beta/openai/",
            ),
        }

    if provider == "ollama":
        return {
            "provider": "ollama",
            # Ollama's OpenAI-compatible endpoint does not require a real key.
            "api_key": _value(config, "api_key", "OLLAMA_API_KEY", "ollama"),
            "model": _value(config, "model", "OLLAMA_MODEL", "llama3.2:3b"),
            "base_url": _value(config, "base_url", "OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        }

    return {
        "provider": "groq",
        "api_key": _value(
            config,
            "api_key",
            "GROK_API_KEY",
            os.getenv("GROQ_API_KEY", ""),
        ),
        "model": _value(config, "model", "GROK_MODEL", "openai/gpt-oss-120b"),
        "base_url": _value(config, "base_url", "GROK_BASE_URL", "https://api.groq.com/openai/v1"),
    }


def build_llm(config: dict[str, str] | None = None) -> LLM:
    """Build a CrewAI LLM using the selected provider."""
    settings = provider_settings(config)
    provider = settings["provider"]
    api_key = settings["api_key"]

    if provider != "ollama" and not api_key:
        env_name = "GEMINI_API_KEY" if provider == "gemini" else "GROK_API_KEY"
        raise ValueError(
            f"{env_name} is not configured. Add the selected provider key to Streamlit Secrets."
        )

    model = settings["model"]
    base_url = settings["base_url"]

    # CrewAI's custom_openai mode strips one leading openai/ prefix. Groq's
    # GPT-OSS model ID needs that prefix on the wire.
    if provider == "groq" and "api.groq.com/openai/v1" in base_url:
        if model == "openai/gpt-oss-120b":
            model = "openai/openai/gpt-oss-120b"
        elif model == "gpt-oss-120b":
            model = "openai/openai/gpt-oss-120b"

    return LLM(
        model=model,
        custom_openai=True,
        base_url=base_url,
        api_key=api_key,
        temperature=0.1,
        max_tokens=700,
    )
