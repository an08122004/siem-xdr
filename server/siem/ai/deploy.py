"""Duyệt / từ chối / gỡ đề xuất AI (chạy trong manager — service duy nhất được ghi rules/ai và rules/exceptions).

Nguyên tắc:
  - Người duyệt là Detection Engineer (quyền rules). Ngoại lệ (làm giảm cảnh báo) cần 2 người KHÁC NHAU duyệt; rule
    mới cần 1.
  - Ngay trước khi ghi file, KIỂM TRA LẠI với nhãn mới nhất (case thật vừa xác nhận sau khi đề xuất được tạo)
    và bộ mẫu vàng: không đạt thì không triển khai.
  - Triển khai rule mới = dựng lại rules-dynamic/ai.xml từ MỌI đề xuất đã triển khai trong ES (R72), mỗi đề xuất một
    khối <group>; ghi qua wazuh_rules.write_dynamic (kiểm tra + nạp lại ruleset). Gỡ = dựng lại file không có khối đó.
  - Rule mới vào chế độ CHẠY BÓNG (nhóm shadow, R71): sinh alert để đo nhưng SOAR bỏ qua. Bật chính thức (promote) khi đã
    chạy bóng tối thiểu SHADOW_MIN_DAYS ngày, dưới SHADOW_MAX_ALERTS_PER_DAY alert/ngày và tỉ lệ báo nhầm dưới
    SHADOW_MAX_FP_RATE trên các alert đã có kết luận (SOC-OPERATIONS.md mục 4).
"""
from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import settings, wazuh_exceptions, wazuh_rules
from ..detection.rules import load_rules
from .condition import Rule, RuleException
from .dataset import ESDataSource
from .golden import PublicDatasets
from .wazuh_xml import EMITTER_VERSION, emit, unshadow
from .validate import _app_specific, common_program_only, describe, lab_wrapper, leaves_of, ordinary_hits, weak_values

log = logging.getLogger("ai.deploy")
_ID = re.compile(r"^[a-f0-9]{12}$")
_golden: PublicDatasets | None = None
AI_FILE = "ai.xml"
AI_FIRST, AI_LAST = 109000, 109999
_lock = threading.Lock()          # mọi thay đổi ai.xml đi qua khóa: hai người duyệt cùng lúc không làm mất khối của nhau


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


def _wazuh(fn, *args):
    """Gọi wazuh_exceptions, đổi lỗi sang DeployError (cùng mã HTTP như route /api/v1/exceptions)."""
    try:
        return fn(*args)
    except wazuh_rules.WazuhUnavailable as e:            # không xác nhận được với Wazuh: từ chối (fail closed)
        raise DeployError(503, str(e)) from None
    except wazuh_exceptions.NotFound:
        raise DeployError(404, "không có ngoại lệ này") from None
    except (wazuh_exceptions.Duplicate, wazuh_rules.WazuhRuleError) as e:      # WazuhRuleError là ValueError: bắt trước
        raise DeployError(409, str(e)) from None
    except (ValueError, KeyError) as e:
        raise DeployError(400, f"ngoại lệ không hợp lệ: {e}") from None


def render_ai_file(deployed: list[dict[str, Any]]) -> str:
    """ai.xml dựng từ các đề xuất đã triển khai (theo `deployed_at`): mỗi đề xuất một khối, XML đóng băng lúc duyệt."""
    head = "<!-- Sinh tự động từ đề xuất AI đã duyệt (nguồn sự thật là Elasticsearch). Không sửa tay: dùng nút 'Gỡ' trên console. -->\n"
    blocks = "".join(f'<group name="siem,ai,ai_{p["id"]},">\n{p["wazuh"]["deployed_xml"]}</group>\n'
                     for p in sorted(deployed, key=lambda d: d.get("deployed_at") or ""))
    return head + (blocks or '<group name="siem,ai,">\n</group>\n')


def next_ids(deployed: list[dict[str, Any]], n: int) -> list[int]:
    """n id liền nhau ngay sau id lớn nhất đã dùng trong dải 109000–109999."""
    top = max([i for p in deployed for i in p["wazuh"]["ids"]] or [AI_FIRST - 1])
    if top + n > AI_LAST:
        raise DeployError(409, f"hết dải id rule AI ({AI_FIRST}–{AI_LAST})")
    return list(range(top + 1, top + n + 1))


def _deployed(es, skip: str = "", used: bool = False) -> list[dict[str, Any]]:
    """Đề xuất rule mới đang nằm trong ai.xml (trừ `skip`). ES không đọc được thì từ chối: ghi file từ danh sách thiếu
    sẽ làm mất khối của đề xuất khác. used=True: cả đề xuất đã gỡ (chỉ để tính id: id đã dùng không được giải phóng)."""
    try:
        res = es.search(index=settings.IDX_AI_PROPOSALS, size=1000, query={"bool": {"filter": [
            {"term": {"kind": "new_rule"}}, {"terms": {"status": ["approved", "promoted"] + (["rolled_back"] if used else [])}}]}})
    except Exception as e:  # noqa: BLE001
        raise DeployError(503, f"không đọc được danh sách rule AI đã triển khai: {e}") from None
    docs = [h["_source"] | {"id": h["_source"].get("id") or h["_id"]} for h in res["hits"]["hits"]]
    return [d for d in docs if d["id"] != skip and (d.get("wazuh") or {}).get("ids" if used else "deployed_xml")]


def _publish(deployed: list[dict[str, Any]], api) -> None:
    _wazuh(lambda: wazuh_rules.write_dynamic(AI_FILE, render_ai_file(deployed), api, root=wazuh_rules.DYNAMIC_DIR))


def _deploy_new(es, pid: str, p: dict[str, Any], seq: int, term: int, now: str, api) -> None:
    """Phát ai.xml với khối mới ở chế độ chạy bóng. Lỗi bất kỳ trước khi file ghi xong -> đề xuất vẫn pending."""
    w = p.get("wazuh") or {}
    if w.get("emitter") != EMITTER_VERSION:
        raise DeployError(409, "đề xuất chưa được kiểm định trên Wazuh hoặc bộ dịch đã đổi — cần kiểm định lại")
    day = now[:10] if re.fullmatch(r"\d{4}-\d{2}-\d{2}", now[:10]) else datetime.now(timezone.utc).date().isoformat()
    prop = p["proposal"]
    with _lock:
        fresh, seq, term = _get(es, pid)         # đọc lại trong khóa: người khác có thể đã duyệt / gỡ đề xuất này
        if fresh["status"] != "pending":
            raise DeployError(409, f"đề xuất đang ở trạng thái {fresh['status']}, không duyệt được")
        others = _deployed(es, skip=pid)
        ids = next_ids(_deployed(es, skip=pid, used=True), int(w.get("rules") or 1))
        code = f"AI-{ids[0] % 1000:03d}"
        try:
            em = emit(prop["condition"], domain=w["domain"], first_id=ids[0], level=int(w["level"]), code=code,
                      title=prop["title"], techniques=(prop.get("mitre") or {}).get("technique") or [],
                      groups=["siem", "ai"], shadow_since=day)
        except ValueError as e:                                         # SigmaError: cây không dịch được nữa
            raise DeployError(409, f"không dịch được sang Wazuh XML, cần kiểm định lại: {e}") from None
        p["wazuh"] = w | {"ids": em.ids, "deployed_xml": em.xml, "code": code, "shadow_since": day}
        p.update(status="approved", deployed_at=now, file=f"rules-dynamic/{AI_FILE}")
        p["history"].append({"at": now, "by": "hệ thống",
                             "text": f"đã triển khai {p['file']} (rule {em.ids[0]}–{em.ids[-1]}, chạy bóng)"})
        _publish(others + [p], api)
        _save(es, pid, p, seq, term)       # shortcut: file đã ghi mà lưu ES lỗi thì lệch tới lần dựng lại kế tiếp


def approve(es, pid: str, analyst: str, api, now: str = "") -> dict[str, Any]:
    p, seq, term = _get(es, pid)
    if p["status"] != "pending":
        raise DeployError(409, f"đề xuất đang ở trạng thái {p['status']}, không duyệt được")
    if any(a["by"].lower() == analyst.lower() for a in p.get("approvals", [])):
        raise DeployError(400, "mỗi analyst chỉ duyệt 1 lần — cần người duyệt khác")
    p["approvals"] = p.get("approvals", []) + [{"by": analyst, "at": now}]
    p["updated_at"] = now
    p.setdefault("history", []).append({"at": now, "by": analyst, "text": "duyệt"})
    if p.get("kind") == "exception" and len(p["approvals"]) >= int(p.get("required_approvals", 1)):
        # R73: người duyệt tạo ngoại lệ Wazuh ở trạng thái chờ duyệt; người thứ hai duyệt ở trang ngoại lệ
        ex = p["proposal"]
        item = _wazuh(wazuh_exceptions.add, ex["rule"], ex["conditions"], ex.get("reason") or "AI đề xuất", analyst, api)
        p.update(status="approved", deployed_at=now, exception_id=item["id"])
        p["history"].append({"at": now, "by": "hệ thống",
                             "text": f"đã tạo ngoại lệ Wazuh #{item['id']} (chờ người khác duyệt ở trang ngoại lệ)"})
    elif len(p["approvals"]) >= int(p.get("required_approvals", 1)):
        problems = recheck(p, es, settings.RULES_DIR)
        if problems:
            p["status"] = "invalid"
            p["history"].append({"at": now, "by": "hệ thống", "text": "kiểm tra lại thất bại: " + "; ".join(problems)})
            _save(es, pid, p, seq, term)
            raise DeployError(409, "không triển khai: " + "; ".join(problems))
        _deploy_new(es, pid, p, seq, term, now, api)
        log.warning("triển khai đề xuất AI %s -> %s (duyệt: %s)", pid, p["file"], [a["by"] for a in p["approvals"]])
        return p
    _save(es, pid, p, seq, term)
    return p


def shadow_stats(es, rule_ids: list[str], since: str | None, now: str = "") -> dict[str, Any]:
    """Số alert chạy bóng của các rule (`WZH-<id>`) kể từ `since` (YYYY-MM-DD) tới `now` (ISO, mặc định giờ hiện tại) và
    kết luận analyst đã ghi."""
    flt: list[dict[str, Any]] = [{"terms": {"rule.id": rule_ids}}, {"term": {"alert.shadow": True}}]
    if since:
        flt.append({"range": {"@timestamp": {"gte": since}}})
    try:
        res = es.search(index=settings.IDX_ALERTS, size=0, query={"bool": {"filter": flt}},
                        aggs={"v": {"terms": {"field": "alert.verdict", "size": 10}}})
        total = res["hits"]["total"]["value"]
        verdicts = {b["key"]: b["doc_count"] for b in res["aggregations"]["v"]["buckets"]}
    except Exception as e:  # noqa: BLE001 - chưa có alert nào: index / trường chưa có mapping
        log.debug("không đếm được alert chạy bóng của %s: %s", rule_ids, e)
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


def promote(es, pid: str, who: str, api, now: str = "") -> dict[str, Any]:
    """Bật chính thức rule AI đang chạy bóng (R71): bỏ nhóm shadow + shadow_since khỏi khối của đề xuất, ghi ai bật, lúc
    nào, số liệu lúc bật. Rule viết tay chạy bóng thì bật bằng commit qua CI, không qua đây."""
    p, seq, term = _get(es, pid)
    w = p.get("wazuh") or {}
    if p.get("kind") != "new_rule" or p["status"] != "approved" or not w.get("shadow_since"):
        raise DeployError(409, "đề xuất không ở chế độ chạy bóng")
    stats = shadow_stats(es, [f"WZH-{i}" for i in w["ids"]], w["shadow_since"], now)
    if (problems := promotion_problems(stats)):
        raise DeployError(409, "chưa đạt tiêu chí bật chính thức: " + "; ".join(problems))
    with _lock:
        fresh, seq, term = _get(es, pid)
        if fresh["status"] != "approved" or not (fresh.get("wazuh") or {}).get("shadow_since"):
            raise DeployError(409, "đề xuất không ở chế độ chạy bóng")
        p, w = fresh, fresh["wazuh"]
        others = _deployed(es, skip=pid)
        w = {k: v for k, v in w.items() if k != "shadow_since"} | {"deployed_xml": unshadow(w["deployed_xml"]), "promoted_at": now}
        p.update(wazuh=w, updated_at=now, promoted_at=now, promoted_by=who)
        p.setdefault("history", []).append({"at": now, "by": who, "text": f"bật chính thức {w['code']} sau chạy bóng: "
                                            f"{stats['alerts']} alert / {stats['days']} ngày"})
        _publish(others + [p], api)
        _save(es, pid, p, seq, term)
    log.warning("bật chính thức rule AI %s bởi %s (%s)", pid, who, stats)
    return {"proposal_id": pid, "mode": "active", "stats": stats}


def reject(es, pid: str, analyst: str, reason: str, now: str = "") -> dict[str, Any]:
    p, seq, term = _get(es, pid)
    if p["status"] not in ("pending", "invalid"):
        raise DeployError(409, f"đề xuất đang ở trạng thái {p['status']}")
    p.update(status="rejected", reject_reason=reason, rejected_by=analyst, updated_at=now)
    p.setdefault("history", []).append({"at": now, "by": analyst, "text": f"từ chối: {reason}"})
    _save(es, pid, p, seq, term)
    return p


def rollback(es, pid: str, analyst: str, reason: str, api, now: str = "") -> dict:
    p, seq, term = _get(es, pid)
    if p["status"] != "approved":
        raise DeployError(409, "chỉ gỡ được đề xuất đã triển khai")
    done = {"status": "rolled_back", "reject_reason": reason, "updated_at": now}
    note = {"at": now, "by": analyst, "text": f"gỡ: {reason}"}
    if p.get("kind") == "exception":
        _wazuh(wazuh_exceptions.remove, int(p["exception_id"]), analyst, reason, api)
        p.update(done)
        p.setdefault("history", []).append(note)
        _save(es, pid, p, seq, term)
    else:
        with _lock:
            p, seq, term = _get(es, pid)                   # đọc lại trong khóa
            if p["status"] != "approved":
                raise DeployError(409, "chỉ gỡ được đề xuất đã triển khai")
            _publish(_deployed(es, skip=pid), api)         # dựng lại ai.xml không có khối này
            p.update(done)
            p.setdefault("history", []).append(note)
            _save(es, pid, p, seq, term)
    log.warning("gỡ đề xuất AI %s bởi %s", pid, analyst)
    return p
