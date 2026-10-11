"""Duyệt / từ chối / gỡ đề xuất AI (chạy trong manager — service duy nhất được ghi rules/ai và rules/exceptions).

Nguyên tắc:
  - Ngoại lệ (làm giảm cảnh báo) cần 2 analyst KHÁC NHAU duyệt; rule mới cần 1.
  - Ngay trước khi ghi file, KIỂM TRA LẠI với nhãn mới nhất (case thật vừa xác nhận sau khi đề xuất được tạo)
    và bộ mẫu vàng: không đạt thì không triển khai.
  - Triển khai = ghi 1 file YAML riêng cho mỗi đề xuất -> analyzer tự nạp lại; gỡ = xóa đúng file đó.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any


from .. import settings
from ..detection.rules import Rule, RuleException, load_rules
from .dataset import ESDataSource
from .golden import PublicDatasets
from .sigma import dump
from .validate import _app_specific, describe, leaves_of, ordinary_hits, weak_values

log = logging.getLogger("ai.deploy")
_ID = re.compile(r"^[a-f0-9]{12}$")
_golden: PublicDatasets | None = None


class DeployError(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code


def golden() -> PublicDatasets:
    global _golden
    if _golden is None:
        _golden = PublicDatasets.load(max_normal=5000)
    return _golden


def _get(es, pid: str) -> tuple[dict[str, Any], int, int]:
    if not _ID.match(pid):
        raise DeployError(400, "id đề xuất không hợp lệ")
    try:
        r = es.get(index=settings.IDX_AI_PROPOSALS, id=pid)
    except Exception:  # noqa: BLE001
        raise DeployError(404, "không tìm thấy đề xuất") from None
    return r["_source"], r["_seq_no"], r["_primary_term"]


def _save(es, pid: str, doc: dict[str, Any], seq: int, term: int) -> None:
    try:
        es.index(index=settings.IDX_AI_PROPOSALS, id=pid, document=doc, if_seq_no=seq, if_primary_term=term,
                 refresh="wait_for")
    except Exception:  # noqa: BLE001
        raise DeployError(409, "đề xuất vừa được người khác cập nhật, hãy tải lại") from None


def target_file(p: dict[str, Any], rules_dir: Path) -> Path:
    if p["kind"] == "exception":
        return rules_dir / "exceptions" / f"{p['id']}.yml"
    rid = p["proposal"]["id"]
    if not re.match(r"^AI-\d{3,}$", rid):
        raise DeployError(400, "ID rule AI không hợp lệ")
    return rules_dir / "ai" / f"{rid}.yml"


def recheck(p: dict[str, Any], es, rules_dir: Path) -> list[str]:
    """Kiểm tra lại ngay trước khi triển khai. Trả về danh sách lý do KHÔNG được triển khai."""
    problems = []
    rules = {r.id: r for r in load_rules(rules_dir)}
    if p["kind"] == "exception":
        rule = rules.get(p["target_rule_id"])
        if not rule:
            return [f"rule {p['target_rule_id']} không còn tồn tại"]
        ex = RuleException.from_dict(p["proposal"])
        ev = ESDataSource(es).evidence().get(rule.id)
        if ev and (n := sum(ex.match(d) for d in ev.tp)):
            problems.append(f"ngoại lệ khớp {n} event của case thật (mới xác nhận sau khi AI đề xuất)")
        if (n := sum(ex.match(x.doc) for x in golden().positives_for(rule))):
            problems.append(f"ngoại lệ làm mất {n} mẫu tấn công của bộ mẫu vàng")
    else:
        if p["proposal"]["id"] in rules:
            problems.append(f"ID {p['proposal']['id']} đã tồn tại")
        rule = Rule.from_dict(p["proposal"])
        if str(p.get("target", "")).startswith("gap-dataset:"):
            problems += recheck_dataset_rule(p["proposal"], rule, golden())
    return problems


def recheck_dataset_rule(rd: dict[str, Any], rule: Rule, g: PublicDatasets) -> list[str]:
    """Rule học từ dataset: đối chiếu lại với tập bình thường và các kiểm tra 'dùng chung được' HIỆN TẠI. Tập lệnh
    bình thường / dấu vết môi trường thử được bổ sung sau khi AI đề xuất thì đề xuất cũ đang chờ vẫn bị chặn."""
    problems = []
    tags = set(rd.get("tags") or [])
    platform = next((t for t in ("windows", "linux") if t in tags), None)
    endpoint = "endpoint" in tags
    normal = g.normal_for("endpoint", platform) if endpoint else g.normal_for("web")
    hits = [d for d in normal if rule.condition.match(d)]
    if normal and len(hits) > 0.001 * len(normal):
        what = f"lệnh {platform or 'endpoint'} bình thường" if endpoint else "request bình thường"
        problems.append(f"rule khớp {len(hits)}/{len(normal)} {what}, vd: {describe(hits[0])[:120]}")
    cond = rd.get("condition") or {}
    positive = leaves_of(cond, positive_only=True)          # rule Sigma: cây lồng all / any / not
    if (tied := _app_specific(positive, set() if endpoint else g.profile.app_tokens())):
        problems.append(f"rule chỉ khớp dữ liệu của dataset (chứa {', '.join(sorted(tied)[:5])})")
    if (weak := weak_values(cond)):
        problems.append(f"đoạn dòng lệnh quá ngắn hoặc chỉ là một từ trơn, không phải chữ ký: {', '.join(weak[:5])}")
    if any(c.get("field", "").startswith("url.") for c in positive) and (oh := ordinary_hits(rule.condition)):
        problems.append(f"rule khớp URL bình thường: {', '.join(oh[:3])}")
    return problems


def _write(path: Path, p: dict[str, Any], approvers: list[str]) -> None:
    header = (f"# Sinh bởi AI worker (model {p.get('llm', {}).get('model')}), đề xuất {p['id']}\n"
              f"# Duyệt bởi: {', '.join(approvers)} — {p['updated_at']}\n"
              f"# Gỡ: nút 'Gỡ' trên console (hoặc xóa file này). Không sửa tay để còn truy vết.\n"
              + ("# Khóa `sigma`: rule Sigma AI viết (nguồn); `condition`: bản đã biên dịch mà analyzer chạy.\n"
                 if p["proposal"].get("sigma") else ""))
    body = dump([p["proposal"]])
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(header + body, encoding="utf-8", newline="\n")
    tmp.replace(path)


def approve(es, pid: str, analyst: str, rules_dir: Path = settings.RULES_DIR, now: str = "") -> dict[str, Any]:
    p, seq, term = _get(es, pid)
    if p["status"] != "pending":
        raise DeployError(409, f"đề xuất đang ở trạng thái {p['status']}, không duyệt được")
    if any(a["by"].lower() == analyst.lower() for a in p.get("approvals", [])):
        raise DeployError(400, "mỗi analyst chỉ duyệt 1 lần — cần người duyệt khác")
    p["approvals"] = p.get("approvals", []) + [{"by": analyst, "at": now}]
    p["updated_at"] = now
    p.setdefault("history", []).append({"at": now, "by": analyst, "text": "duyệt"})
    if len(p["approvals"]) >= int(p.get("required_approvals", 1)):
        problems = recheck(p, es, rules_dir)
        if problems:
            p["status"] = "invalid"
            p["history"].append({"at": now, "by": "hệ thống", "text": "kiểm tra lại thất bại: " + "; ".join(problems)})
            _save(es, pid, p, seq, term)
            raise DeployError(409, "không triển khai: " + "; ".join(problems))
        path = target_file(p, rules_dir)
        _write(path, p, [a["by"] for a in p["approvals"]])
        p.update(status="approved", deployed_at=now, file=str(path.relative_to(rules_dir)).replace("\\", "/"))
        p["history"].append({"at": now, "by": "hệ thống", "text": f"đã triển khai {p['file']}"})
        log.warning("triển khai đề xuất AI %s -> %s (duyệt: %s)", pid, p["file"], [a["by"] for a in p["approvals"]])
    _save(es, pid, p, seq, term)
    return p


def reject(es, pid: str, analyst: str, reason: str, now: str = "") -> dict[str, Any]:
    p, seq, term = _get(es, pid)
    if p["status"] not in ("pending", "invalid"):
        raise DeployError(409, f"đề xuất đang ở trạng thái {p['status']}")
    p.update(status="rejected", reject_reason=reason, rejected_by=analyst, updated_at=now)
    p.setdefault("history", []).append({"at": now, "by": analyst, "text": f"từ chối: {reason}"})
    _save(es, pid, p, seq, term)
    return p


def rollback(es, pid: str, analyst: str, reason: str, rules_dir: Path = settings.RULES_DIR, now: str = "") -> dict:
    p, seq, term = _get(es, pid)
    if p["status"] != "approved":
        raise DeployError(409, "chỉ gỡ được đề xuất đã triển khai")
    path = target_file(p, rules_dir)
    if path.exists():
        path.unlink()
    p.update(status="rolled_back", reject_reason=reason, updated_at=now)
    p.setdefault("history", []).append({"at": now, "by": analyst, "text": f"gỡ: {reason}"})
    _save(es, pid, p, seq, term)
    log.warning("gỡ đề xuất AI %s (%s) bởi %s", pid, path.name, analyst)
    return p
