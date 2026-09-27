"""Client Ollama (LLM chạy nội bộ, không gửi dữ liệu ra ngoài) — chỉ dùng thư viện chuẩn.

Dùng "structured output": truyền JSON schema vào tham số `format`, Ollama ép model
sinh ĐÚNG cấu trúc đó (ràng buộc bằng grammar). Nhờ vậy output luôn parse được và
model không thể chèn văn bản tự do / chỉ dẫn lạ vào kết quả.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("ai.llm")


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    data: dict[str, Any]
    raw: str
    model: str
    seconds: float
    prompt_tokens: int
    output_tokens: int


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: int = 300, num_ctx: int = 8192, max_tokens: int = 1024):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.max_tokens = max_tokens  # chặn cứng độ dài output: tránh model sinh vô hạn (treo worker)

    def _post(self, path: str, body: dict[str, Any], timeout: int | None = None) -> dict[str, Any]:
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise LLMError(f"Ollama {path} trả về {e.code}: {e.read()[:300]!r}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LLMError(f"không gọi được Ollama {self.base_url}: {e}") from e

    def available_models(self) -> list[str]:
        req = urllib.request.Request(self.base_url + "/api/tags")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return [m["name"] for m in json.loads(r.read()).get("models", [])]
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LLMError(f"không kết nối được Ollama {self.base_url}: {e}") from e

    def ensure_model(self) -> None:
        """Tải model về nếu chưa có (lần đầu có thể mất vài phút, ~4-5 GB)."""
        names = self.available_models()
        if any(n == self.model or n.split(":")[0] == self.model for n in names):
            return
        log.warning("chưa có model %s — đang tải về (lần đầu có thể mất nhiều phút)...", self.model)
        self._post("/api/pull", {"model": self.model, "stream": False}, timeout=7200)
        log.info("đã tải xong model %s", self.model)

    def chat_json(self, system: str, user: str, schema: dict[str, Any], temperature: float = 0.2) -> LLMResult:
        t0 = time.time()
        res = self._post("/api/chat", {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": schema,
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": self.num_ctx, "num_predict": self.max_tokens},
        })
        raw = (res.get("message") or {}).get("content", "")
        if res.get("done_reason") == "length":
            raise LLMError(f"output vượt {self.max_tokens} token, bị cắt — bỏ qua ứng viên này")
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise LLMError(f"output không phải JSON: {raw[:200]!r}") from e
        if not isinstance(data, dict):
            raise LLMError("output JSON không phải object")
        return LLMResult(data=data, raw=raw, model=res.get("model", self.model), seconds=round(time.time() - t0, 1),
                         prompt_tokens=int(res.get("prompt_eval_count") or 0),
                         output_tokens=int(res.get("eval_count") or 0))
