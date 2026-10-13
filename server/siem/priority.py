"""Mức ưu tiên P1–P4 và SLA của alert / case (SOC-OPERATIONS.md mục 2).

Ưu tiên = mức độ của rule kết hợp mức quan trọng của tài sản (config/assets.yml, trường asset.criticality của event).
Tài sản không có trong danh mục coi là `medium`: khi đó ưu tiên đúng như cách cũ theo severity (critical = P1 ...).
SLA mỗi mức gồm: xác nhận (analyst nhận xử lý), khoanh vùng xong, chu kỳ cập nhật trạng thái. Bảng và ma trận có thể
ghi đè trong config/priority.yml.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

CRITICALITY = ("low", "medium", "high", "critical")
PRIORITIES = ("P1", "P2", "P3", "P4")
# severity -> ưu tiên theo mức quan trọng tài sản low / medium / high / critical
DEFAULT_MATRIX: dict[str, tuple[str, str, str, str]] = {
    "critical": ("P2", "P1", "P1", "P1"),
    "high": ("P3", "P2", "P2", "P1"),
    "medium": ("P4", "P3", "P3", "P2"),
    "low": ("P4", "P4", "P4", "P3"),
}
# phút; `update` = chu kỳ cập nhật trạng thái cho lãnh đạo (None: cập nhật khi đóng)
DEFAULT_SLA: dict[str, dict[str, int | None]] = {
    "P1": {"ack": 15, "contain": 60, "update": 60},
    "P2": {"ack": 30, "contain": 240, "update": 240},
    "P3": {"ack": 120, "contain": 1440, "update": None},
    "P4": {"ack": 480, "contain": 4320, "update": None},
}


class Policy:
    def __init__(self, matrix: dict[str, tuple[str, ...]] | None = None,
                 sla: dict[str, dict[str, int | None]] | None = None):
        self.matrix = {k: tuple(v) for k, v in (matrix or DEFAULT_MATRIX).items()}
        self.sla = {k: dict(v) for k, v in (sla or DEFAULT_SLA).items()}
        for sev, row in self.matrix.items():
            if len(row) != len(CRITICALITY) or any(p not in PRIORITIES for p in row):
                raise ValueError(f"priority.yml: dòng {sev} phải có 4 mức P1-P4")
        for p in PRIORITIES:
            if p not in self.sla or not self.sla[p].get("ack") or not self.sla[p].get("contain"):
                raise ValueError(f"priority.yml: thiếu SLA ack / contain của {p}")

    @classmethod
    def load(cls, path: Path | None) -> "Policy":
        if not path or not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        sla = {**DEFAULT_SLA, **(data.get("sla") or {})}
        return cls({**DEFAULT_MATRIX, **(data.get("matrix") or {})}, sla)

    def priority(self, severity: str | None, criticality: str | None = None) -> str:
        row = self.matrix.get(str(severity or "medium").lower(), self.matrix["medium"])
        crit = str(criticality or "medium").lower()
        return row[CRITICALITY.index(crit) if crit in CRITICALITY else 1]

    def dues(self, start: str, priority: str) -> dict[str, str]:
        """Hạn xác nhận / khoanh vùng tính từ `start` (ISO)."""
        t0 = datetime.fromisoformat(start)
        s = self.sla.get(priority, self.sla["P3"])
        return {"ack_due": (t0 + timedelta(minutes=int(s["ack"]))).isoformat(),
                "contain_due": (t0 + timedelta(minutes=int(s["contain"]))).isoformat()}


def higher(a: str | None, b: str | None) -> bool:
    """`a` ưu tiên cao hơn `b` (P1 cao nhất; không có mức coi là thấp nhất)."""
    return bool(a) and (not b or str(a) < str(b))


def seconds_between(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    try:
        d = (datetime.fromisoformat(str(end).replace("Z", "+00:00")) -
             datetime.fromisoformat(str(start).replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return None
    return round(max(d, 0.0), 1)


def met(done_at: str | None, due: str | None) -> bool | None:
    """Đạt SLA? None nếu chưa có hạn hoặc chưa làm và chưa quá hạn (chưa kết luận được)."""
    if not due:
        return None
    due_t = datetime.fromisoformat(due)
    if done_at:
        return datetime.fromisoformat(done_at) <= due_t
    return False if datetime.now(timezone.utc) > due_t else None


_policy: Policy | None = None


def policy() -> Policy:
    """Chính sách dùng chung trong tiến trình (đọc config/priority.yml một lần)."""
    global _policy
    if _policy is None:
        from . import settings
        try:
            _policy = Policy.load(settings.CONFIG_DIR / "priority.yml")
        except Exception as e:  # noqa: BLE001 - file cấu hình hỏng không được làm dừng pipeline
            log.error("priority.yml lỗi, dùng bảng mặc định: %s", e)
            _policy = Policy()
    return _policy


def set_policy(p: Policy | None) -> None:
    """Dùng cho test."""
    global _policy
    _policy = p
