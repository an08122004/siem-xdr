"""Case playbook: chọn quy trình xử lý sự cố phù hợp cho alert và dựng checklist task.

Cấu hình: config/case_playbooks.yml (playbook đầu tiên có `match` khớp rule.id được chọn).
"""
from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("soar.cases")

PHASES = ["Phát hiện & phân tích", "Ngăn chặn", "Loại bỏ", "Khôi phục", "Rút kinh nghiệm"]
_DEFAULT_PRIORITY = {"critical": ("P1", 15), "high": ("P2", 60), "medium": ("P3", 480), "low": ("P4", 1440)}


class CasePlaybooks:
    def __init__(self, path: Path | None):
        self.playbooks: list[dict[str, Any]] = []
        self.priority = dict(_DEFAULT_PRIORITY)
        if path and path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for sev, p in (data.get("priority") or {}).items():
                self.priority[sev] = (p["level"], int(p["sla_minutes"]))
            self.playbooks = data.get("playbooks") or []
            for pb in self.playbooks:
                for ph in pb.get("phases", []):
                    if ph["name"] not in PHASES:
                        raise ValueError(f"{pb['id']}: giai đoạn không hợp lệ '{ph['name']}'")
        log.info("đã nạp %d case playbook", len(self.playbooks))

    def select(self, rule_id: str) -> dict[str, Any] | None:
        for pb in self.playbooks:
            if any(fnmatch.fnmatch(rule_id, str(p)) for p in pb.get("match", [])):
                return pb
        return None

    def build(self, rule_id: str, severity: str) -> dict[str, Any]:
        """Trả về các trường gắn vào case mới: playbook, tasks, priority, sla_due."""
        level, minutes = self.priority.get(severity, _DEFAULT_PRIORITY["medium"])
        fields: dict[str, Any] = {
            "priority": level,
            "sla_due": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(),
            "playbook": None,
            "tasks": [],
        }
        pb = self.select(rule_id)
        if not pb:
            return fields
        fields["playbook"] = {"id": pb["id"], "name": pb["name"]}
        for ph in pb.get("phases", []):
            for t in ph.get("tasks", []):
                task = t if isinstance(t, dict) else {"title": t}
                fields["tasks"].append({
                    "phase": ph["name"], "title": task["title"], "approval": task.get("approval"),
                    "done": False, "done_by": None, "done_at": None,
                })
        return fields
