"""Duyệt / từ chối / gỡ đề xuất AI (chạy trong manager — service duy nhất được ghi rules/ai và rules/exceptions).

Nguyên tắc:
  - Người duyệt là Detection Engineer (quyền rules). Ngoại lệ (làm giảm cảnh báo) cần 2 người KHÁC NHAU duyệt; rule
    mới cần 1.
  - Ngay trước khi ghi file, KIỂM TRA LẠI với nhãn mới nhất (case thật vừa xác nhận sau khi đề xuất được tạo)
    và bộ mẫu vàng: không đạt thì không triển khai.
  - Triển khai = ghi 1 file YAML riêng cho mỗi đề xuất -> analyzer tự nạp lại; gỡ = xóa đúng file đó.
  - Rule mới vào chế độ CHẠY BÓNG (mode: shadow): sinh alert để đo nhưng SOAR bỏ qua. Bật chính thức (promote) khi đã
    chạy bóng tối thiểu SHADOW_MIN_DAYS ngày, dưới SHADOW_MAX_ALERTS_PER_DAY alert/ngày và tỉ lệ báo nhầm dưới
    SHADOW_MAX_FP_RATE trên các alert đã có kết luận (SOC-OPERATIONS.md mục 4).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .. import settings
from ..detection.rules import Rule, RuleException, load_rules
from .dataset import ESDataSource
from .golden import PublicDatasets
from .sigma import dump
from .validate import _app_specific, common_program_only, describe, lab_wrapper, leaves_of, ordinary_hits, weak_values

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
    tokens = g.lab_tokens(platform) if endpoint else g.profile.app_tokens()
    if (tied := sorted(_app_specific(positive, tokens)) + [f"lớp bọc {v!r}" for v in lab_wrapper(cond)]):
        problems.append(f"rule chỉ khớp dữ liệu của dataset (chứa {', '.join(tied[:5])})")
    if (weak := weak_values(cond)):
        problems.append(f"đoạn dòng lệnh quá ngắn hoặc chỉ là một từ trơn, không phải chữ ký: {', '.join(weak[:5])}")
    if (bare := common_program_only(cond)):
        problems.append(f"vế chỉ có tên chương trình phổ biến, không đối số nào: {', '.join(sorted(set(bare))[:5])}")
    if any(c.get("field", "").startswith("url.") for c in positive) and (oh := ordinary_hits(rule.condition)):
        problems.append(f"rule khớp URL bình thường: {', '.join(oh[:3])}")
    return problems


def deployed_rule(p: dict[str, Any], approvers: list[str], now: str) -> dict[str, Any]:
    """Rule ghi ra file: đề xuất + metadata bắt buộc của kho rule (detection/lint.py) + chế độ chạy bóng. Ngoại lệ ghi
    nguyên đề xuất. Nguồn log và ghi chú báo nhầm lấy từ rule Sigma AI viết."""
    rule = dict(p["proposal"])
    if p["kind"] == "exception":
        return rule
    try:
        sig = yaml.safe_load(rule.get("sigma") or "") or {}
    except yaml.YAMLError:
        sig = {}
    sig = sig if isinstance(sig, dict) else {}
    fps = [str(x) for x in sig.get("falsepositives") or [] if str(x).strip() and str(x).lower() != "unknown"]
    rule.setdefault("logsource", sig.get("logsource") or {"product": "unknown"})
    rule.setdefault("owner", ", ".join(approvers))
    rule.setdefault("falsepositives", fps or ["Chưa biết: AI không nêu; xem alert chạy bóng trước khi bật chính thức"])
    day = now[:10] if re.match(r"^\d{4}-\d{2}-\d{2}$", now[:10]) else datetime.now(timezone.utc).date().isoformat()
    rule.update(mode="shadow", shadow_since=day)
    return rule


def _write(path: Path, p: dict[str, Any], approvers: list[str]) -> None:
    header = (f"# Sinh bởi AI worker (model {p.get('llm', {}).get('model')}), đề xuất {p['id']}\n"
              f"# Duyệt bởi: {', '.join(approvers)} — {p['updated_at']}\n"
              f"# Gỡ: nút 'Gỡ' trên console (hoặc xóa file này). Không sửa tay để còn truy vết.\n"
              + ("# Khóa `sigma`: rule Sigma AI viết (nguồn); `condition`: bản đã biên dịch mà analyzer chạy.\n"
                 if p["proposal"].get("sigma") else "")
              + ("# mode: shadow = chạy bóng (SOAR bỏ qua); Detection Engineer bấm 'Bật chính thức' khi đạt tiêu chí.\n"
                 if p["kind"] != "exception" else ""))
    body = dump([deployed_rule(p, approvers, p.get("updated_at") or "")])
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


def shadow_stats(es, rule_id: str, since: str | None, now: str = "") -> dict[str, Any]:
    """Số alert chạy bóng của rule kể từ `since` (YYYY-MM-DD) tới `now` (ISO, mặc định giờ hiện tại) và kết luận
    analyst đã ghi."""
    flt: list[dict[str, Any]] = [{"term": {"rule.id": rule_id}}, {"term": {"alert.shadow": True}}]
    if since:
        flt.append({"range": {"@timestamp": {"gte": since}}})
    try:
        res = es.search(index=settings.IDX_ALERTS, size=0, query={"bool": {"filter": flt}},
                        aggs={"v": {"terms": {"field": "alert.verdict", "size": 10}}})
        total = res["hits"]["total"]["value"]
        verdicts = {b["key"]: b["doc_count"] for b in res["aggregations"]["v"]["buckets"]}
    except Exception as e:  # noqa: BLE001 - chưa có alert nào: index / trường chưa có mapping
        log.debug("không đếm được alert chạy bóng của %s: %s", rule_id, e)
        total, verdicts = 0, {}
    start = datetime.fromisoformat(since).replace(tzinfo=timezone.utc) if since else None
    try:
        ref = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
    except ValueError:
        ref = datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    days = (ref - start).total_seconds() / 86400 if start else 0.0
    judged = sum(verdicts.values())
    return {"since": since, "days": round(days, 1), "alerts": total,
            "alerts_per_day": round(total / max(days, 1.0), 2), "judged": judged,
            "fp_rate": round(verdicts.get("false_positive", 0) / judged, 3) if judged else None, "verdicts": verdicts}


def promotion_problems(stats: dict[str, Any]) -> list[str]:
    out = []
    if stats["days"] < settings.SHADOW_MIN_DAYS:
        out.append(f"mới chạy bóng {stats['days']} ngày, cần tối thiểu {settings.SHADOW_MIN_DAYS}")
    if stats["alerts_per_day"] >= settings.SHADOW_MAX_ALERTS_PER_DAY:
        out.append(f"{stats['alerts_per_day']} alert/ngày, cần dưới {settings.SHADOW_MAX_ALERTS_PER_DAY}")
    if stats["fp_rate"] is not None and stats["fp_rate"] >= settings.SHADOW_MAX_FP_RATE:
        out.append(f"tỉ lệ báo nhầm {stats['fp_rate']:.0%}, cần dưới {settings.SHADOW_MAX_FP_RATE:.0%}")
    return out


_MODE_LINE = re.compile(r"^(\s*)mode: shadow\s*$", re.M)


def promote(es, rule_id: str, who: str, rules_dir: Path = settings.RULES_DIR, now: str = "") -> dict[str, Any]:
    """Bật chính thức rule AI đang chạy bóng (rules/ai/<id>.yml): đổi mode, ghi ai bật, lúc nào, số liệu lúc bật.
    Rule viết tay chạy bóng thì bật bằng commit đổi `mode` trong kho rule (qua CI), không qua đây."""
    if not re.match(r"^AI-\d{3,}$", rule_id):
        raise DeployError(400, "chỉ bật được rule AI (AI-xxx) trên console; rule viết tay đổi mode qua kho rule")
    path = rules_dir / "ai" / f"{rule_id}.yml"
    if not path.exists():
        raise DeployError(404, f"không có file rule {rule_id}")
    text = path.read_text(encoding="utf-8")
    rule = next((d for d in yaml.safe_load(text) or [] if isinstance(d, dict) and str(d.get("id")) == rule_id), None)
    if not rule or rule.get("mode") != "shadow" or not _MODE_LINE.search(text):
        raise DeployError(409, f"{rule_id} không ở chế độ chạy bóng")
    stats = shadow_stats(es, rule_id, rule.get("shadow_since"), now)
    if (problems := promotion_problems(stats)):
        raise DeployError(409, "chưa đạt tiêu chí bật chính thức: " + "; ".join(problems))
    note = (f"\\1mode: active\n\\1promoted: {{by: {who}, at: '{now}', alerts_per_day: {stats['alerts_per_day']}, "
            f"fp_rate: {stats['fp_rate'] if stats['fp_rate'] is not None else 'null'}}}")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(_MODE_LINE.sub(note, text, count=1), encoding="utf-8", newline="\n")
    tmp.replace(path)
    pid = rule.get("ai_proposal_id")
    if pid and _ID.match(str(pid)):
        try:
            p, seq, term = _get(es, str(pid))
            p.setdefault("history", []).append({"at": now, "by": who, "text": f"bật chính thức {rule_id} sau chạy bóng: "
                                                f"{stats['alerts']} alert / {stats['days']} ngày"})
            p.update(updated_at=now, promoted_at=now, promoted_by=who)
            _save(es, str(pid), p, seq, term)
        except DeployError as e:            # file đã đổi; lịch sử đề xuất ghi không được thì chỉ log
            log.warning("bật %s: không ghi được lịch sử đề xuất %s: %s", rule_id, pid, e)
    log.warning("bật chính thức rule AI %s bởi %s (%s)", rule_id, who, stats)
    return {"rule_id": rule_id, "mode": "active", "stats": stats}


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
