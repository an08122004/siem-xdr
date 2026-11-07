"""Client của sandbox Wazuh cô lập (R67): service compose `wazuh-sandbox` (profile ai, network_mode none, cùng image
wazuh-manager). Worker giao job qua thư mục trên volume ai_sandbox, KHÔNG có docker socket; giao thức và cách runner xử lý
một job ở wazuh/sandbox/runner.py.

Sandbox hỏng (runner không chạy, hết giờ, canary 554 không ra, gửi thiếu / analysisd bỏ event) -> SandboxError: bên gọi
ghi lỗi chu kỳ, KHÔNG được coi là "rule không bắt". Ruleset không nạp được (rule ứng viên sai) -> SandboxResult.load_error.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .. import settings
from .wazuh_events import RawEvent

_AGENT = re.compile(r"\bsbx-(\d+)\b")


class SandboxError(RuntimeError):
    """Sandbox Wazuh không cho kết quả tin được."""


@dataclass
class Hit:
    rule_id: int
    level: int


@dataclass
class SandboxResult:
    hits: dict[int, list[Hit]]          # ident -> mọi alert của event đó
    load_error: str | None
    seconds: float


def alert_ident(alert: dict) -> int | None:
    """ident của event sinh ra alert: eventchannel = EventRecordID; còn lại = header agent "(sbx-<ident>)", alert ghi ở
    agent.name (đo S4; location chỉ còn đường dẫn, vẫn xem cho chắc)."""
    rid = (((alert.get("data") or {}).get("win") or {}).get("system") or {}).get("eventRecordID")
    if rid:
        return int(rid)
    for v in ((alert.get("agent") or {}).get("name"), alert.get("location")):
        if isinstance(v, str) and (m := _AGENT.search(v)):
            return int(m.group(1))
    return None


class Sandbox:
    def __init__(self, root: Path = settings.AI_SANDBOX_DIR, timeout: float = settings.AI_SANDBOX_TIMEOUT):
        self.root, self.timeout = Path(root), timeout

    def run(self, events: list[RawEvent], candidate_xml: str | None = None) -> SandboxResult:
        """Bơm `events` (kèm rule ứng viên `candidate_xml` nếu có) vào sandbox, trả alert theo ident."""
        idents = {e.ident for e in events}
        if len(idents) != len(events):
            raise ValueError("ident của event phải khác nhau (dùng để ghép alert)")
        t0 = time.monotonic()
        job = self.root / "jobs" / secrets.token_hex(6)
        try:
            job.mkdir(parents=True)
            (job / "events.jsonl").write_text("".join(json.dumps({"msg": e.msg}) + "\n" for e in events),
                                              encoding="utf-8", newline="\n")
            if candidate_xml is not None:
                (job / "candidate.xml").write_text(candidate_xml, encoding="utf-8", newline="\n")
            (job / "ready").touch()                 # cuối cùng: runner chỉ nhận job đã ghi xong
            while not (job / "done").exists():
                if time.monotonic() - t0 > self.timeout:
                    raise SandboxError(f"sandbox Wazuh chạy quá {self.timeout:g} giây chưa xong job "
                                       "(container wazuh-sandbox không chạy hoặc quá tải)")
                time.sleep(0.2)
            res = json.loads((job / "result.json").read_text(encoding="utf-8"))
            alerts_file = job / "alerts.jsonl"
            alerts = ([json.loads(line) for line in alerts_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                      if alerts_file.exists() else [])
        except (OSError, ValueError) as e:
            raise SandboxError(f"không giao / đọc được job của sandbox Wazuh ({self.root}): {e}") from e
        finally:
            shutil.rmtree(job, ignore_errors=True)
        seconds = round(time.monotonic() - t0, 1)
        if res.get("load_error"):
            return SandboxResult({}, str(res["load_error"]), seconds)
        if res.get("error"):
            raise SandboxError(f"runner sandbox Wazuh lỗi: {res['error']}")
        if not res.get("canary"):
            raise SandboxError("event canary (rule 554) không ra alert: analysisd không chạy hoặc chưa xử lý xong")
        if int(res.get("sent", 0)) < len(events) or int(res.get("dropped", 0)):
            raise SandboxError(f"analysisd không nhận đủ event: gửi {res.get('sent')}/{len(events)}, "
                               f"bỏ {res.get('dropped')}")
        hits: dict[int, list[Hit]] = {}
        for a in alerts:
            if (i := alert_ident(a)) in idents:
                r = a.get("rule") or {}
                hits.setdefault(i, []).append(Hit(int(r["id"]), int(r.get("level", 0))))
        return SandboxResult(hits, None, seconds)
