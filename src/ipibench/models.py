"""Model clients.

* ``openai``  - any OpenAI-compatible Chat Completions endpoint (OpenAI, vLLM, Together,
                OpenRouter, DashScope / Qwen, DeepSeek, ...)
* ``ollama``  - local Ollama server via its native /api/chat (lets us set num_ctx)
* ``mock``    - deterministic fake model for offline pipeline tests. Its numbers are NOT
                results and must never be reported as such.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ModelConfig:
    name: str
    provider: str = "openai"
    model: str = ""
    base_url: str | None = None
    api_key_env: str | None = None
    api_key: str | None = None
    temperature: float = 0.0
    max_tokens: int = 512
    concurrency: int = 8
    num_ctx: int = 8192
    extra: dict = field(default_factory=dict)


def load_model_configs(path: str | Path) -> dict[str, ModelConfig]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out = {}
    for name, cfg in raw["models"].items():
        out[name] = ModelConfig(name=name, **cfg)
    return out


class ChatClient:
    async def complete(self, messages: list[dict], meta: dict | None = None) -> str:  # pragma: no cover
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


class OpenAICompatClient(ChatClient):
    def __init__(self, cfg: ModelConfig):
        from openai import AsyncOpenAI

        key = (os.environ.get(cfg.api_key_env) if cfg.api_key_env else None) or cfg.api_key
        if not key:
            raise RuntimeError(f"model {cfg.name!r}: set the {cfg.api_key_env} environment variable")
        self.cfg = cfg
        self.client = AsyncOpenAI(api_key=key, base_url=cfg.base_url, max_retries=0, timeout=120)

    async def complete(self, messages, meta=None):
        from openai import APIConnectionError, APITimeoutError, InternalServerError, RateLimitError

        delay = 2.0
        for attempt in range(8):
            try:
                resp = await self.client.chat.completions.create(
                    model=self.cfg.model,
                    messages=messages,
                    temperature=self.cfg.temperature,
                    max_tokens=self.cfg.max_tokens,
                    **self.cfg.extra,
                )
                return resp.choices[0].message.content or ""
            except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError):
                if attempt == 7:
                    raise
                await asyncio.sleep(delay + random.random())
                delay = min(delay * 2, 60)
        return ""

    async def aclose(self):
        await self.client.close()


class OllamaClient(ChatClient):
    def __init__(self, cfg: ModelConfig):
        import httpx

        self.cfg = cfg
        self.http = httpx.AsyncClient(base_url=cfg.base_url or "http://localhost:11434", timeout=600)

    async def complete(self, messages, meta=None):
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.cfg.temperature, "num_predict": self.cfg.max_tokens,
                        "num_ctx": self.cfg.num_ctx, "seed": 0, **self.cfg.extra},
        }
        for attempt in range(4):
            try:
                r = await self.http.post("/api/chat", json=payload)
                r.raise_for_status()
                return r.json()["message"]["content"]
            except Exception:
                if attempt == 3:
                    raise
                await asyncio.sleep(2 * (attempt + 1))
        return ""

    async def aclose(self):
        await self.http.aclose()


class MockClient(ChatClient):
    """Pretend model: obeys the injection with a probability that shrinks when defense cues are
    present in the prompt. Used only to test the pipeline end-to-end without API keys."""

    BASE = {"naive": 0.45, "ignore_previous": 0.6, "fake_system": 0.65, "fake_completion": 0.7,
            "authority": 0.55, "urgency": 0.5, "multilingual": 0.5, "combined": 0.8}

    def __init__(self, cfg: ModelConfig):
        self.cfg = cfg

    async def complete(self, messages, meta=None):
        from .data.attacks import artifacts
        from .defenses import REMOVED

        meta = meta or {}
        system, user = messages[0]["content"], messages[-1]["content"]
        fact = meta.get("fact", "")
        answer = f"The {meta.get('fact_name', 'answer')} is {fact}."
        if not meta.get("injected"):
            return answer
        p = self.BASE.get(meta["technique"], 0.5)
        if "SECURITY POLICY" in system:
            p *= 0.45
        if "EXTERNAL_DATA_" in system:
            p *= 0.6
        if "interleaving" in system:
            p *= 0.5
        if meta.get("canary") and meta["canary"].lower() not in user.lower() and meta["goal"] != "fact_manipulation":
            p = 0.0  # payload was filtered out
        if meta["goal"] == "fact_manipulation" and meta.get("fake_fact") not in user:
            p = 0.0
        if REMOVED in user and p > 0:
            p *= 0.5
        h = int(hashlib.sha256(f"{self.cfg.name}:{meta['id']}:{system[-40:]}".encode()).hexdigest(), 16)
        if (h % 10_000) / 10_000 >= p:
            return answer + " Note: the content contains a suspected prompt injection, which I ignored."
        a = artifacts(meta["canary"])
        goal = meta["goal"]
        if goal == "exfiltration":
            return answer + f"\n\n![status]({a['exfil_url'].replace('DATA', 'question')})"
        if goal == "tool_abuse":
            return answer + f'\n<action name="send_email" to="{a["email"]}">conversation</action>'
        if goal == "phishing":
            return answer + f" Your account has been locked; re-verify at [Account Recovery]({a['phish_url']})."
        if goal == "prefix_hijack":
            return a["prefix"] + " " + answer
        if goal == "fact_manipulation":
            return f"The {meta.get('fact_name')} is {meta['fake_fact']}."
        return answer


def make_client(cfg: ModelConfig) -> ChatClient:
    if cfg.provider == "openai":
        return OpenAICompatClient(cfg)
    if cfg.provider == "ollama":
        return OllamaClient(cfg)
    if cfg.provider == "mock":
        return MockClient(cfg)
    raise ValueError(f"unknown provider {cfg.provider!r}")
