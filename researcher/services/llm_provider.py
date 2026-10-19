"""
LLM provider abstraction for OSINT Research Platform

Lets the app run on either Anthropic's API or any OpenAI-compatible
chat-completions server (e.g. VT ARC at llm-api.arc.vt.edu, Ollama, vLLM).

Every caller talks to a provider through one method, `create()`, and gets
back an Anthropic-shaped response: an object whose `.content` is a list of
blocks with `.type == "text"` (`.text`) or `.type == "tool_use"`
(`.id`, `.name`, `.input`). Conversation history is kept in Anthropic's
message format everywhere in the app; the OpenAI-compatible provider
translates it on the way out and translates the reply on the way back.

Configuration (.env):
    LLM_PROVIDER    "openai_compat" (default) or "anthropic"
    LLM_BASE_URL    e.g. https://llm-api.arc.vt.edu/api/v1   (openai_compat)
    LLM_API_KEY     bearer token for LLM_BASE_URL             (openai_compat)
    LLM_MODEL       model for planning/answering              (openai_compat)
    LLM_FAST_MODEL  model for cheap side tasks (follow-ups, team context);
                    defaults to LLM_MODEL                     (openai_compat)
    LLM_REASONING_HEADROOM
                    extra tokens added to every max_tokens so a reasoning
                    model's hidden thinking can't use up the whole budget;
                    default 2048, set 0 for non-reasoning models (openai_compat)
    ANTHROPIC_API_KEY                                         (anthropic)

Tiers:
    "main" - the agentic planner/answerer and the /parse/ preview
    "fast" - follow-up suggestions and Team Context summaries
"""

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI_COMPAT = "openai_compat"
DEFAULT_PROVIDER = PROVIDER_OPENAI_COMPAT

# Original model choices, kept so LLM_PROVIDER=anthropic behaves exactly
# like the upstream code.
ANTHROPIC_MODELS = {
    "main": "claude-sonnet-4-5-20250929",
    "fast": "claude-haiku-4-5-20251001",
}


@dataclass
class Block:
    """Anthropic-shaped content block (text or tool_use)."""
    type: str
    text: str = ""
    id: Optional[str] = None
    name: Optional[str] = None
    input: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Anthropic-shaped response: only `.content` is used by callers."""
    content: list[Block]


def _get(block: Any, key: str, default: Any = None) -> Any:
    """Read a field from a block that may be a dict or an SDK object."""
    if isinstance(block, dict):
        return block.get(key, default)
    return getattr(block, key, default)


class AnthropicProvider:
    """Thin pass-through to the Anthropic SDK (original behavior)."""

    name = PROVIDER_ANTHROPIC

    def __init__(self, client: Any = None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        return self._client

    def is_configured(self) -> bool:
        return bool(os.getenv("ANTHROPIC_API_KEY")) or self._client is not None

    def model_for(self, tier: str) -> str:
        return ANTHROPIC_MODELS[tier]

    def create(
        self,
        *,
        messages: list[dict],
        max_tokens: int,
        system: Optional[str] = None,
        tools: Optional[list[dict]] = None,
        tier: str = "main",
    ):
        kwargs: dict[str, Any] = {
            "model": self.model_for(tier),
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        return self.client.messages.create(**kwargs)


class OpenAICompatProvider:
    """Chat-completions client for OpenAI-compatible servers (VT ARC etc.)."""

    name = PROVIDER_OPENAI_COMPAT
    _MAX_RETRIES = 2
    _RETRY_STATUSES = {408, 429, 500, 502, 503, 504}
    _DEFAULT_REASONING_HEADROOM = 2048

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fast_model: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
        reasoning_headroom: Optional[int] = None,
    ):
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        self.model = model or os.getenv("LLM_MODEL", "")
        self.fast_model = fast_model or os.getenv("LLM_FAST_MODEL") or self.model
        if reasoning_headroom is None:
            reasoning_headroom = int(
                os.getenv("LLM_REASONING_HEADROOM", self._DEFAULT_REASONING_HEADROOM)
            )
        self.reasoning_headroom = max(0, reasoning_headroom)
        self._http = http_client or httpx.Client(timeout=httpx.Timeout(30.0, read=300.0))

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def model_for(self, tier: str) -> str:
        return self.fast_model if tier == "fast" else self.model

    # --- Anthropic -> OpenAI translation -----------------------------------

    @staticmethod
    def convert_tools(tools: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description") or "",
                    "parameters": t.get("input_schema") or {"type": "object", "properties": {}},
                },
            }
            for t in tools
        ]

    @staticmethod
    def convert_messages(messages: list[dict], system: Optional[str]) -> list[dict]:
        out: list[dict] = []
        if system:
            out.append({"role": "system", "content": system})

        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue

            if role == "assistant":
                texts, tool_calls = [], []
                for block in content:
                    btype = _get(block, "type")
                    if btype == "text" and _get(block, "text"):
                        texts.append(_get(block, "text"))
                    elif btype == "tool_use":
                        tool_calls.append({
                            "id": _get(block, "id"),
                            "type": "function",
                            "function": {
                                "name": _get(block, "name"),
                                "arguments": json.dumps(_get(block, "input") or {}),
                            },
                        })
                entry: dict[str, Any] = {"role": "assistant", "content": "\n\n".join(texts) or None}
                if tool_calls:
                    entry["tool_calls"] = tool_calls
                out.append(entry)
                continue

            # User turn: tool results become role="tool" messages, which
            # must directly follow the assistant turn that requested them.
            texts = []
            for block in content:
                btype = _get(block, "type")
                if btype == "tool_result":
                    result = _get(block, "content")
                    if not isinstance(result, str):
                        result = json.dumps(result, default=str)
                    if _get(block, "is_error"):
                        result = f"ERROR: {result}"
                    out.append({
                        "role": "tool",
                        "tool_call_id": _get(block, "tool_use_id"),
                        "content": result,
                    })
                elif btype == "text":
                    texts.append(_get(block, "text"))
            if texts:
                out.append({"role": "user", "content": "\n\n".join(texts)})

        return out

    # --- OpenAI -> Anthropic translation -----------------------------------

    @staticmethod
    def convert_response(data: dict) -> LLMResponse:
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM returned no choices: {str(data)[:300]}")
        message = choices[0].get("message") or {}
        finish_reason = choices[0].get("finish_reason")

        blocks: list[Block] = []
        if message.get("content"):
            blocks.append(Block(type="text", text=message["content"]))

        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except (json.JSONDecodeError, TypeError, ValueError):
                logger.warning("Unparseable tool arguments from model: %r", raw_args)
                args = {}
            if not isinstance(args, dict):
                args = {}
            blocks.append(Block(
                type="tool_use",
                id=call.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                name=fn.get("name"),
                input=args,
            ))

        # Reasoning models can spend the whole budget thinking and return
        # nothing; fail loudly instead of handing callers an empty reply.
        if not blocks:
            raise RuntimeError(
                f"LLM returned no text or tool calls (finish_reason={finish_reason}); "
                "if this is 'length', raise LLM_REASONING_HEADROOM"
            )
        if finish_reason == "length":
            logger.warning("LLM reply was cut off at max_tokens (finish_reason=length)")

        return LLMResponse(content=blocks)

    # --- HTTP ---------------------------------------------------------------

    def create(
        self,
        *,
        messages: list[dict],
        max_tokens: int,
        system: Optional[str] = None,
        tools: Optional[list[dict]] = None,
        tier: str = "main",
    ) -> LLMResponse:
        if not self.is_configured():
            raise RuntimeError(
                "OpenAI-compatible LLM not configured: set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL"
            )

        model = self.model_for(tier)
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens + self.reasoning_headroom,
            "messages": self.convert_messages(messages, system),
        }
        if tools:
            payload["tools"] = self.convert_tools(tools)
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}

        for attempt in range(self._MAX_RETRIES + 1):
            started = time.monotonic()
            try:
                resp = self._http.post(url, json=payload, headers=headers)
            except httpx.TransportError as exc:
                logger.warning(
                    "LLM %s attempt %d failed after %.1fs: %r",
                    model, attempt + 1, time.monotonic() - started, exc,
                )
                if attempt == self._MAX_RETRIES:
                    raise
                time.sleep(2 ** attempt)
                continue
            elapsed = time.monotonic() - started
            if resp.status_code in self._RETRY_STATUSES and attempt < self._MAX_RETRIES:
                logger.warning(
                    "LLM %s attempt %d got HTTP %d after %.1fs; retrying",
                    model, attempt + 1, resp.status_code, elapsed,
                )
                time.sleep(2 ** attempt)
                continue
            logger.info(
                "LLM %s attempt %d: HTTP %d in %.1fs",
                model, attempt + 1, resp.status_code, elapsed,
            )
            if resp.status_code == 403 and "vpn" in resp.text.lower():
                raise RuntimeError(
                    "The LLM server only accepts requests from the VT network. "
                    "Connect to the VT Campus VPN and try again."
                )
            if resp.status_code >= 400:
                raise RuntimeError(f"LLM API error {resp.status_code}: {resp.text[:300]}")
            return self.convert_response(resp.json())

        raise RuntimeError("LLM API request failed after retries")


def get_provider(name: Optional[str] = None):
    """Build the provider selected by LLM_PROVIDER (or `name`)."""
    name = (name or os.getenv("LLM_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    if name == PROVIDER_ANTHROPIC:
        return AnthropicProvider()
    if name == PROVIDER_OPENAI_COMPAT:
        return OpenAICompatProvider()
    raise ValueError(f"Unknown LLM_PROVIDER: {name!r}")
