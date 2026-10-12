"""Case playbook: chọn quy trình xử lý sự cố phù hợp cho alert và dựng checklist task.

Cấu hình: config/case_playbooks.yml. Chọn playbook theo thứ tự:
  1. `match`: mã rule (wildcard), playbook đầu tiên trong file khớp; mẫu "*" của playbook mặc định để dành cho bước 4
  2. `techniques`: kỹ thuật MITRE ATT&CK của rule, khớp cụ thể nhất thắng (T1098.004 thắng T1098; T1003 khớp T1003.001)
  3. `tags`: tag của rule (vd nhóm rule Wazuh: syscheck, rootcheck, virustotal...)
  4. playbook có `match: ["*"]`
Bước 2, 3 dành cho rule không biết trước mã: rule do AI viết (AI-xxx), cảnh báo ruleset Wazuh (WZH-<id>).

Mỗi task có `title`, tùy chọn `approval` (ai được quyết định) và `detail` (cách làm cụ thể: lệnh, event ID, chỗ xem
trên console). `common`: task chung cho MỌI playbook (ghi chứng cứ, timeline, báo cáo sau sự cố...), đặt đầu
(`position: first`) hoặc cuối giai đoạn. `references`: nguồn tham khảo của playbook, hiện trên case.
"""
from __future__ import annotations

import fnmatch
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

log = logging.getLogger("soar.cases")

PHASES = ["Phát hiện & phân tích", "Ngăn chặn", "Loại bỏ", "Khôi phục", "Rút kinh nghiệm"]
_DEFAULT_PRIORITY = {"critical": ("P1", 15), "high": ("P2", 60), "medium": ("P3", 480), "low": ("P4", 1440)}
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _task(t: Any) -> dict[str, Any]:
    return t if isinstance(t, dict) else {"title": t}


class CasePlaybooks:
    def __init__(self, path: Path | None):
        self.playbooks: list[dict[str, Any]] = []
        self.common: list[dict[str, Any]] = []
        self.priority = dict(_DEFAULT_PRIORITY)
        if path and path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for sev, p in (data.get("priority") or {}).items():
                self.priority[sev] = (p["level"], int(p["sla_minutes"]))
            self.playbooks = data.get("playbooks") or []
            self.common = data.get("common") or []
            for c in self.common:
                if c["phase"] not in PHASES or c.get("position", "last") not in ("first", "last"):
                    raise ValueError(f"common: giai đoạn / vị trí không hợp lệ '{c['phase']}' / '{c.get('position')}'")
            for pb in self.playbooks:
                for ph in pb.get("phases", []):
                    if ph["name"] not in PHASES:
                        raise ValueError(f"{pb['id']}: giai đoạn không hợp lệ '{ph['name']}'")
                    for t in ph.get("tasks", []):
                        if not str(_task(t).get("title") or "").strip():
                            raise ValueError(f"{pb['id']}: task không có title trong '{ph['name']}'")
                for t in pb.get("techniques", []):
                    if not _TECHNIQUE.match(str(t)):
                        raise ValueError(f"{pb['id']}: mã kỹ thuật MITRE không hợp lệ '{t}'")
        log.info("đã nạp %d case playbook, %d nhóm task chung", len(self.playbooks), len(self.common))

    def select(self, rule_id: str, techniques: Iterable[str] = (), tags: Iterable[str] = ()
               ) -> tuple[dict[str, Any] | None, str]:
        """(playbook, lý do chọn) theo thứ tự trong docstring của module."""
        for pb in self.playbooks:
            for p in pb.get("match", []):
                if str(p) != "*" and fnmatch.fnmatch(rule_id, str(p)):
                    return pb, f"mã rule {p}"
        techniques = [str(t) for t in techniques or []]
        best: tuple[dict[str, Any], str] | None = None
        for pb in self.playbooks:
            for t in pb.get("techniques", []):
                t = str(t)
                if any(x == t or x.startswith(t + ".") for x in techniques) and (best is None or len(t) > len(best[1])):
                    best = (pb, t)
        if best:
            return best[0], f"kỹ thuật MITRE {best[1]}"
        tags = {str(t) for t in tags or []}
        for pb in self.playbooks:
            if hit := sorted(tags & {str(t) for t in pb.get("tags", [])}):
                return pb, f"tag {hit[0]}"
        for pb in self.playbooks:
            if "*" in [str(p) for p in pb.get("match", [])]:
                return pb, "mặc định"
        return None, ""

    def build(self, rule_id: str, severity: str, techniques: Iterable[str] = (), tags: Iterable[str] = ()
              ) -> dict[str, Any]:
        """Trả về các trường gắn vào case mới: playbook, tasks, priority, sla_due."""
        level, minutes = self.priority.get(severity, _DEFAULT_PRIORITY["medium"])
        fields: dict[str, Any] = {
            "priority": level,
            "sla_due": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(),
            "playbook": None,
            "tasks": [],
        }
        pb, why = self.select(rule_id, techniques, tags)
        if not pb:
            return fields
        fields["playbook"] = {"id": pb["id"], "name": pb["name"], "matched_by": why}
        fields["references"] = [r if isinstance(r, dict) else {"title": str(r)} for r in pb.get("references", [])]
        own = {ph["name"]: ph.get("tasks", []) for ph in pb.get("phases", [])}
        common = lambda phase, pos: [t for c in self.common   # noqa: E731
                                     if c["phase"] == phase and c.get("position", "last") == pos for t in c["tasks"]]
        for phase in PHASES:                                    # luôn theo thứ tự 5 giai đoạn
            for t in common(phase, "first") + own.get(phase, []) + common(phase, "last"):
                task = _task(t)
                fields["tasks"].append({
                    "phase": phase, "title": task["title"], "approval": task.get("approval"),
                    "detail": task.get("detail"), "done": False, "done_by": None, "done_at": None,
                })
        return fields
