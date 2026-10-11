"""Client Ollama (LLM chạy nội bộ, không gửi dữ liệu ra ngoài) — chỉ dùng thư viện chuẩn.

Đề xuất ngoại lệ dùng "structured output": truyền JSON schema vào tham số `format`, Ollama ép model sinh
ĐÚNG cấu trúc đó (ràng buộc bằng grammar). Rule mới là rule Sigma (YAML, chat_text): grammar JSON không áp
được, câu trả lời được parse chặt (sigma.parse) và kiểm định độc lập — văn bản thừa bị bỏ qua.
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


class LLMTooLong(LLMError):
    """Câu trả lời vượt giới hạn token (bị cắt): lỗi của câu trả lời, không phải của Ollama."""


@dataclass
class LLMResult:
    data: dict[str, Any]
    raw: str
    model: str
    seconds: float
    prompt_tokens: int
    output_tokens: int


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: int = 300, num_ctx: int = 8192, max_tokens: int = 1024,
                 think: bool = False):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.max_tokens = max_tokens  # chặn cứng độ dài output: tránh model sinh vô hạn (treo worker)
        # model có chế độ suy nghĩ (qwen3, qwen3.5...): mặc định TẮT — phần suy nghĩ dài gấp nhiều lần câu trả lời,
        # đầu ra đã bị ép theo JSON schema. Chỉ gửi tham số `think` cho model khai báo có khả năng này.
        self.think = think
        self._thinking: bool | None = None

    # Ollama khởi động lại giữa chu kỳ (máy ngủ dậy, tạo lại container): 10/10 mất 2 đề xuất vì "Connection refused" /
    # "Remote end closed connection". Chỉ thử lại lỗi KẾT NỐI; hết thời gian chờ thì không (sinh lại mất thêm vài phút).
    RETRY_WAIT = (10, 30)

    def _post(self, path: str, body: dict[str, Any], timeout: int | None = None) -> dict[str, Any]:
        for wait in (*self.RETRY_WAIT, None):
            req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                    return json.loads(r.read() or b"{}")
            except urllib.error.HTTPError as e:
                raise LLMError(f"Ollama {path} trả về {e.code}: {e.read()[:300]!r}") from e
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                reason = getattr(e, "reason", e)
                if wait is None or not isinstance(reason, (ConnectionRefusedError, ConnectionResetError)):
                    raise LLMError(f"không gọi được Ollama {self.base_url}: {e}") from e
                log.warning("Ollama chưa sẵn sàng (%s) — thử lại sau %d giây", reason, wait)
                time.sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

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

    def supports_thinking(self) -> bool:
        if self._thinking is None:
            try:
                info = self._post("/api/show", {"model": self.model}, timeout=30)
                self._thinking = "thinking" in (info.get("capabilities") or [])
            except LLMError:
                self._thinking = False
        return self._thinking

    def _chat(self, system: str, user: str, temperature: float, schema: dict[str, Any] | None) -> tuple[dict, str, float]:
        t0 = time.time()
        res = self._post("/api/chat", {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            **({"format": schema} if schema is not None else {}),
            "stream": False,
            **({"think": self.think} if self.supports_thinking() else {}),
            "options": {"temperature": temperature, "num_ctx": self.num_ctx,
                        "num_predict": self.max_tokens * (4 if self.think else 1)},
        })
        if res.get("done_reason") == "length":
            raise LLMTooLong(f"output vượt {self.max_tokens} token, bị cắt — bỏ qua ứng viên này")
        return res, (res.get("message") or {}).get("content", ""), round(time.time() - t0, 1)

    def _result(self, res: dict, data: dict[str, Any], raw: str, seconds: float) -> LLMResult:
        return LLMResult(data=data, raw=raw, model=res.get("model", self.model), seconds=seconds,
                         prompt_tokens=int(res.get("prompt_eval_count") or 0),
                         output_tokens=int(res.get("eval_count") or 0))

    def chat_json(self, system: str, user: str, schema: dict[str, Any], temperature: float = 0.2) -> LLMResult:
        res, raw, sec = self._chat(system, user, temperature, schema)
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise LLMError(f"output không phải JSON: {raw[:200]!r}") from e
        if not isinstance(data, dict):
            raise LLMError("output JSON không phải object")
        return self._result(res, data, raw, sec)

    def chat_text(self, system: str, user: str, temperature: float = 0.2) -> LLMResult:
        """Văn bản tự do (rule Sigma dạng YAML): grammar JSON không áp được cho YAML; bên gọi tự parse và kiểm định,
        độ dài vẫn bị chặn bởi num_predict."""
        res, raw, sec = self._chat(system, user, temperature, None)
        return self._result(res, {}, raw, sec)
