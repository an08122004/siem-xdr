"""AI worker: mỗi chu kỳ tìm chỗ cần cải thiện rule -> hỏi LLM -> kiểm định -> lưu ĐỀ XUẤT chờ duyệt.

Ba nguồn ứng viên:
  1. exception   — rule có nhiều alert bị analyst đánh dấu false positive (nhãn thật từ case / console)
  2. gap-dataset — mẫu tấn công trong dataset công khai mà chưa rule nào bắt: web gom theo LOẠI tấn công
                   (attack_types.py), endpoint Windows / Linux gom theo KỸ THUẬT ATT&CK (Atomic Red Team);
                   tách tập đưa cho LLM / tập kiểm tra, xếp lượt xen kẽ web / Windows / Linux
  3. gap-own     — nhóm event thật (module/category/action) chưa có rule nào xem xét
Worker KHÔNG ghi file rule, KHÔNG có quyền sửa gì ngoài index ai-*.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

import yaml

from .. import settings
from ..detection.rules import Rule, load_rules, regex_risk
from ..pipeline.normalize import Doc, get
from .attack_types import TYPES
from .dataset import ESDataSource, EventGroup
from .deploy import recheck_dataset_rule
from .golden import OS_NAME, PublicDatasets
from . import sigma
from .llm import LLMError, LLMResult, LLMTooLong, OllamaClient
from .prompts import (EXCEPTION_SCHEMA, EXCEPTION_SYSTEM, SIGMA_KNOWLEDGE_SYSTEM, SIGMA_REFINE_SYSTEM, SIGMA_SYSTEM,
                      exception_prompt, rule_to_yaml, sigma_knowledge_prompt, sigma_refine_prompt, sigma_rule_prompt,
                      sigma_view)
from .sigma import SigmaError
from .validate import (Check, Validation, _app_specific, build_condition, common_program_only, describe, lab_wrapper,
                       leaves_of, ordinary_hits, scope_match, validate_exception, validate_new_rule, weak_values)

log = logging.getLogger("ai.worker")
OPEN = ["pending", "approved"]
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
T = TypeVar("T")
# tăng khi đổi cách chọn mẫu / ghép mẫu / kiểm định (không đổi prompt) để đề xuất cũ bị loại được thử lại
# 7: rule mới viết bằng Sigma (7/10); 8: nới / tổng quát hóa vế Sigma (8/10);
# 9: vế ứng viên SigmaHQ, lượt hỏi kiến thức, tập bình thường lớn hơn (8/10);
# 10: chặn vế chỉ có tên chương trình phổ biến / lớp bọc `& {` / tên file bài thử tự đặt, trần số vế SigmaHQ (11/10)
GENERATOR_REVISION = "10"
DOMAIN_ORDER = ("web", "windows", "linux")
MIN_GAP_EVENTS = 10          # nhóm web / EVTX: số mẫu tối thiểu
MIN_GAP_TESTS = 4            # nhóm Atomic Red Team: số bài thử tối thiểu (tách đôi train / kiểm tra theo bài thử)
MAX_UNVERIFIED = 8           # vế của model (lượt đầu + lượt kiến thức) giữ lại dù chưa khớp mẫu train (xem _refine)
MAX_UNVERIFIED_SIGMAHQ = 10  # vế từ rule SigmaHQ cùng kỹ thuật giữ lại dù chưa khớp mẫu train (endpoint)
# ... và tối đa bấy nhiêu VẾ: một rule như "Netcat Reverse Shell" khai triển thành hàng chục vế (chạy thật 11/10: AI-153
# mang 44 vế SigmaHQ chưa kiểm chứng; bench 9/10 trung vị 15 vế / rule) — quá dài cho người duyệt
MAX_UNVERIFIED_SIGMAHQ_ATOMS = 12
# mỗi vế phải có ít nhất một điều kiện trên các trường mang chữ ký (theo tiền tố)
SIGNATURE_FIELDS = {"web": ("url.", "user_agent."),
                    "windows": ("process.command_line", "process.name", "process.executable", "process.parent."),
                    "linux": ("process.command_line", "process.name", "process.executable", "process.parent.")}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generator_id(model: str) -> str:
    """Dấu vân tay của model + system prompt + phiên bản logic sinh rule (GENERATOR_REVISION), ghi vào mỗi đề xuất.
    Đổi một trong ba thì mục tiêu từng bị kiểm định loại được thử lại ngay."""
    return hashlib.sha1("\n".join([model, EXCEPTION_SYSTEM, SIGMA_SYSTEM, SIGMA_REFINE_SYSTEM, SIGMA_KNOWLEDGE_SYSTEM,
                                   GENERATOR_REVISION]).encode()).hexdigest()[:10]


def _path_key(d: Doc) -> str:
    return str(get(d, "url.path") or get(d, "event.action") or "")


def diverse(items: list[T], k: int, key: Callable[[T], str] = _path_key) -> list[T]:
    """Chọn k mẫu trải đều theo `key` (mặc định url.path): mỗi nhóm 1 mẫu, nhóm ĐÔNG trước; còn chỗ thì chia
    thêm theo tỉ lệ kích thước nhóm (D'Hondt) để nhóm lớn có nhiều mẫu hơn nhóm lẻ tẻ.
    Nhờ vậy LLM thấy các biến thể phổ biến nhất, thay vì k mẫu liền nhau cùng một nhóm (hoặc k nhóm đầu
    bảng chữ cái: bản cũ xếp theo tên nên 8 mẫu dò đường dẫn đều là /CFIDE/...). Tất định (không ngẫu nhiên)."""
    groups: dict[str, list[T]] = defaultdict(list)
    for x in items:
        groups[key(x)].append(x)
    queues = [q for _, q in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    out = [q[0] for q in queues[:k]]
    taken = [1 if i < k else 0 for i in range(len(queues))]
    while len(out) < k:
        left = [i for i, q in enumerate(queues) if taken[i] < len(q)]
        if not left:
            break
        i = max(left, key=lambda j: len(queues[j]) / (taken[j] + 1))
        out.append(queues[i][taken[i]])
        taken[i] += 1
    return out


def rule_yaml(rule: Rule) -> str:
    """Tìm lại YAML gốc của rule để đưa cho LLM (RAG: đúng rule cần tinh chỉnh)."""
    path = settings.RULES_DIR / rule.source_file if rule.source_file else None
    if path and path.exists():
        text = path.read_text(encoding="utf-8")
        m = re.search(rf"^- id: {re.escape(rule.id)}\n(?:(?!^- id: ).*\n?)*", text, re.M)
        if m:
            return m.group(0)
    return f"- id: {rule.id}\n  title: {rule.title}\n  type: {rule.type}\n"


def _test_id(x) -> str:
    return str(x.label.get("guid") or x.label.get("test") or "")


def _proc_key(d: Doc) -> str:
    return str(get(d, "process.name") or "").lower()


def split_subtechniques(key: str, items: list) -> list[tuple[str, list]]:
    """Nhóm kỹ thuật gốc (atomic-red-team:windows-T1218) -> mỗi kỹ thuật con đủ MIN_GAP_TESTS bài thử thành nhóm riêng
    (atomic-red-team:windows-T1218.011); bài thử còn lại (kỹ thuật gốc, kỹ thuật con ít bài thử) giữ khóa cũ."""
    subs: dict[str, list] = defaultdict(list)
    for x in items:
        if "." in str(x.label.get("technique")):
            subs[x.label["technique"]].append(x)
    out, taken = [], set()
    for tid, xs in sorted(subs.items()):
        if len({_test_id(x) for x in xs}) >= MIN_GAP_TESTS:
            out.append((f"{key.rsplit('-', 1)[0]}-{tid}", xs))
            taken |= {id(x) for x in xs}
    rest = [x for x in items if id(x) not in taken]
    return out + ([(key, rest)] if rest else [])


def _program(x) -> str:
    return str(x.label.get("program") or x.label.get("test") or "")


def split_by_test(items: list, variant: Callable[[Any], str]) -> tuple[list, list]:
    """Tách train / kiểm tra theo BÀI THỬ, xen kẽ trong từng biến thể (kỹ thuật con): biến thể nào có từ 2 bài thử
    thì có mặt ở cả hai tập; biến thể chỉ có 1 bài thử nằm ở train. Tất định (xếp theo guid)."""
    tests: dict[str, set[str]] = defaultdict(set)
    for x in items:
        tests[variant(x)].add(_test_id(x))
    held: set[str] = set()
    for v in sorted(tests):
        held |= set(sorted(tests[v])[1::2])
    if not held:          # mỗi biến thể chỉ 1 bài thử -> vẫn phải có tập kiểm tra: xen kẽ trên toàn bộ bài thử
        held = set(sorted(set().union(*tests.values()))[1::2])
    return [x for x in items if _test_id(x) not in held], [x for x in items if _test_id(x) in held]


class AIWorker:
    def __init__(self, es, llm: OllamaClient, golden: PublicDatasets | None,
                 rules_dir: Path = settings.RULES_DIR, ds_factory: Callable[[Any], ESDataSource] = ESDataSource,
                 save: Callable[[dict], None] | None = None):
        self.es = es
        self.llm = llm
        self.golden = golden
        self.rules_dir = rules_dir
        self.ds_factory = ds_factory
        self.save = save or self._save_es

    def _save_es(self, p: dict[str, Any]) -> None:
        self.es.index(index=settings.IDX_AI_PROPOSALS, id=p["id"], document=p, refresh="wait_for")

    # ------------------------------------------------------------------
    def run_cycle(self, requested_by: str | None = None) -> dict[str, Any]:
        rules = load_rules(self.rules_dir)
        ds = self.ds_factory(self.es)
        history = ds.proposals(since="now-30d")
        gen = generator_id(self.llm.model)
        summary = {"started_at": now_iso(), "requested_by": requested_by, "model": self.llm.model,
                   "created": [], "skipped": [], "errors": [], "rechecked": []}
        self._recheck_stale(history, gen, summary)
        open_targets = {p["target"] for p in history if p.get("status") in OPEN}
        rejected: dict[str, list[str]] = defaultdict(list)
        recent_closed = set()
        for p in history:
            st = p.get("status")
            # người từ chối / gỡ -> chặn 30 ngày; kiểm định tự động loại -> chỉ chặn khi CÙNG model + prompt
            # (đổi model hoặc sửa prompt thì thử lại ngay, không phải chờ hết 30 ngày)
            if st in ("rejected", "rolled_back") or \
                    (st in ("invalid", "no_action") and (p.get("llm") or {}).get("generator") == gen):
                recent_closed.add(p["target"])
            if st in ("rejected", "rolled_back") and p.get("reject_reason"):
                rejected[p["target"]].append(p["reject_reason"])
        budget = settings.AI_MAX_PROPOSALS_PER_RUN

        # 1) ngoại lệ cho rule ồn
        evidence = ds.evidence()
        for rule in sorted(rules, key=lambda r: -len(evidence.get(r.id).fp if r.id in evidence else [])):
            ev = evidence.get(rule.id)
            if budget <= 0 or not ev or len(ev.fp) < settings.AI_MIN_FALSE_POSITIVES:
                continue
            target = f"exception:{rule.id}"
            if target in open_targets:
                summary["skipped"].append(f"{target}: đã có đề xuất đang chờ/đã duyệt")
                continue
            self._try(summary, target, lambda: self.propose_exception(rule, ev, ds, rejected[target]))
            budget -= 1

        # 2) khoảng trống so với dataset công khai
        if budget > 0 and self.golden and self.golden.attack:
            for key, missed in self.dataset_gaps(rules):
                if budget <= 0:
                    break
                target = f"gap-dataset:{key}"
                kind = key.rsplit(":", 1)[-1]
                if not PublicDatasets.transferable(kind):
                    summary["skipped"].append(f"{target}: {len(missed)} mẫu — {TYPES[kind].label}, "
                                              "không viết được rule chữ ký dùng chung")
                    continue
                if target in open_targets or target in recent_closed:
                    continue
                self._try(summary, target, lambda: self.propose_dataset_rule(key, missed, rules, ds, rejected[target]))
                budget -= 1

        # 3) nhóm event thật chưa có rule nào xem xét
        if budget > 0:
            for g in ds.event_groups(settings.AI_MIN_GROUP_EVENTS):
                if budget <= 0:
                    break
                target = f"gap-own:{g.key_str}"
                if target in open_targets or target in recent_closed or not g.samples:
                    continue
                if any(scope_match(r, s) for r in rules for s in g.samples):
                    continue
                self._try(summary, target, lambda: self.propose_own_rule(g, rules, ds, rejected[target]))
                budget -= 1

        summary["finished_at"] = now_iso()
        log.info("chu kỳ AI xong: %d đề xuất, %d lỗi", len(summary["created"]), len(summary["errors"]))
        return summary

    def _recheck_stale(self, history: list[dict[str, Any]], gen: str, summary: dict[str, Any]) -> None:
        """Đề xuất rule dataset đang chờ duyệt do logic / model CŨ sinh ra: chạy lại đúng bước kiểm tra lúc duyệt
        (deploy.recheck_dataset_rule: tập bình thường, dấu vết lab, độ đặc trưng HIỆN TẠI). Trượt -> invalid kèm lý do,
        như khi analyst bấm duyệt — để rule chắc chắn không triển khai được không giữ chỗ mãi (target có đề xuất pending
        thì không được đề xuất lại bằng logic mới). Rà soát 11/10: 11/44 đề xuất cũ như vậy. Không tự duyệt / từ chối
        thay người: đề xuất qua được vẫn chờ analyst."""
        if not self.golden:
            return
        for p in history:
            if p.get("status") != "pending" or p.get("kind") != "new_rule" or (p.get("llm") or {}).get("generator") == gen                     or not str(p.get("target", "")).startswith("gap-dataset:"):
                continue
            try:
                problems = recheck_dataset_rule(p["proposal"], Rule.from_dict(p["proposal"]), self.golden)
            except Exception as e:  # noqa: BLE001
                problems = [f"không dựng lại được rule: {e}"]
            if not problems:
                continue
            try:
                cur = self.es.get(index=settings.IDX_AI_PROPOSALS, id=p["id"])
                doc = cur["_source"]
                if doc.get("status") != "pending":
                    continue
                doc.update(status="invalid", updated_at=now_iso())
                doc.setdefault("history", []).append({
                    "at": now_iso(), "by": "ai-worker",
                    "text": "kiểm tra lại theo luật kiểm định hiện tại thất bại (đề xuất do phiên bản cũ của AI worker "
                            "sinh ra): " + "; ".join(problems)})
                self.es.index(index=settings.IDX_AI_PROPOSALS, id=p["id"], document=doc, refresh="wait_for",
                              if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
            except Exception as e:  # noqa: BLE001 — analyst vừa cập nhật đề xuất / ES lỗi: để chu kỳ sau
                log.warning("không kiểm tra lại được đề xuất %s: %s", p.get("id"), e)
                continue
            p["status"] = "invalid"
            summary["rechecked"].append(f"{p['id']} {p.get('title', '')[:80]}: {'; '.join(problems)[:200]}")
            log.info("đề xuất cũ %s không còn qua kiểm định: %s", p["id"], "; ".join(problems)[:200])

    def _try(self, summary: dict, target: str, fn: Callable[[], dict | None]) -> None:
        try:
            p = fn()
        except LLMError as e:
            summary["errors"].append(f"{target}: {e}")
            log.warning("LLM lỗi với %s: %s", target, e)
            return
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"{target}: {e}")
            log.exception("đề xuất %s lỗi", target)
            return
        if p:
            self.save(p)
            summary["created"].append({"id": p["id"], "target": target, "status": p["status"]})

    # ------------------------------------------------------------------
    def _base(self, kind: str, target: str, llm_res, title: str) -> dict[str, Any]:
        return {
            "id": uuid.uuid4().hex[:12], "kind": kind, "target": target, "title": title,
            "status": "pending", "created_at": now_iso(), "updated_at": now_iso(),
            "rationale": str(llm_res.data.get("rationale") or llm_res.data.get("description") or "")[:2000],
            "approvals": [], "history": [{"at": now_iso(), "by": "ai-worker", "text": "tạo đề xuất"}],
            "llm": {"model": llm_res.model, "generator": generator_id(self.llm.model), "seconds": llm_res.seconds,
                    "prompt_tokens": llm_res.prompt_tokens, "output_tokens": llm_res.output_tokens,
                    "raw": llm_res.raw[:8000]},
        }

    def propose_exception(self, rule: Rule, ev, ds: ESDataSource, rejected: list[str]) -> dict[str, Any]:
        res = self.llm.chat_json(EXCEPTION_SYSTEM, exception_prompt(rule_yaml(rule), ev.fp, ev.tp, rejected),
                                 EXCEPTION_SCHEMA)
        pid = uuid.uuid4().hex[:12]
        exc = {"id": f"EXC-{pid}", "rule_id": rule.id,
               "description": str(res.data.get("rationale", ""))[:500],
               "condition": build_condition(res.data.get("match", "all"), res.data.get("clauses") or []),
               "source": "ai", "proposal_id": pid}
        val = validate_exception(rule, exc, ev.fp, ev.tp, self.golden, ds.replay_events())
        p = self._base("exception", f"exception:{rule.id}", res, f"Ngoại lệ cho {rule.id} — {rule.title}")
        p.update(id=pid, target_rule_id=rule.id, proposal=exc, yaml=rule_to_yaml(exc),
                 validation=val.to_dict(), risk=val.risk, required_approvals=2,
                 status="pending" if val.passed else "invalid",
                 evidence={"fp_alert_ids": ev.fp_alert_ids[:200], "tp_alert_ids": ev.tp_alert_ids[:200]})
        return p

    def dataset_gaps(self, rules: list[Rule]) -> list[tuple[str, list]]:
        """Mẫu tấn công dataset chưa rule match nào bắt, gom theo loại tấn công (web), kỹ thuật ATT&CK theo hệ
        điều hành (Atomic Red Team) hoặc tactic (EVTX). Thứ tự: xen kẽ web / Windows / Linux, trong mỗi lĩnh vực
        nhóm đông trước — để ngân sách mỗi chu kỳ không dồn hết cho một lĩnh vực.
        Endpoint: kỹ thuật CON có đủ bài thử thành nhóm riêng (vd windows-T1218.011 Rundll32), phần còn lại ở nhóm
        kỹ thuật gốc (windows-T1218). Chạy thật 4/10: nhóm theo kỹ thuật gốc rộng quá (T1218 gồm >10 LOLBin, T1112
        hàng chục kiểu sửa registry) -> model chỉ viết được chữ ký cho từng bài thử, bắt 2-13% bài thử chưa thấy.
        Trả về cả nhóm riêng ứng dụng (không giao cho AI) để ghi vào tóm tắt chu kỳ."""
        match_rules = [r for r in rules if r.type == "match"]
        groups: dict[str, list] = defaultdict(list)
        for x in self.golden.attack:
            if not any(self.golden.event_hit(r, x.doc) for r in match_rules):
                groups[f"{x.label.get('dataset')}:{self.golden.attack_type(x)}"].append(x)
        by_domain: dict[str, list[tuple[str, list]]] = defaultdict(list)
        for k, v in groups.items():
            parts = split_subtechniques(k, v) if v[0].label.get("guid") else [(k, v)]
            for k2, v2 in parts:
                if len({_test_id(x) for x in v2}) >= MIN_GAP_TESTS if v2[0].label.get("guid") \
                        else len(v2) >= MIN_GAP_EVENTS:
                    by_domain[self.golden.domain(v2[0])].append((k2, v2))
        # nhóm kỹ thuật con (hẹp, viết được chữ ký) trước nhóm kỹ thuật gốc; web không có '.' nên không đổi thứ tự
        queues = [sorted(by_domain[d], key=lambda kv: ("." not in kv[0], -len(kv[1]), kv[0]))
                  for d in sorted(by_domain, key=lambda d: DOMAIN_ORDER.index(d) if d in DOMAIN_ORDER else 9)]
        return [q[i] for i in range(max(map(len, queues), default=0)) for q in queues if i < len(q)]

    def _next_ai_id(self, rules: list[Rule], ds: ESDataSource) -> str:
        nums = [int(m.group(1)) for rid in [r.id for r in rules] + [
            (p.get("proposal") or {}).get("id", "") for p in ds.proposals(since="now-3650d", size=1000)]
            if (m := re.match(r"AI-(\d+)$", str(rid)))]
        return f"AI-{max(nums, default=0) + 1:03d}"

    # ------------------------------------------------------------------ rule mới (Sigma)
    def _ask_sigma(self, system: str, prompt: str, temperature: float = 0.2) -> LLMResult:
        """Hỏi model MỘT rule Sigma. Câu trả lời không đọc được (YAML hỏng, thiếu detection...) thì hỏi lại 1 lần kèm
        lỗi. data = rule đã parse, hoặc {"no_rule": lý do}, hoặc {"_error": lỗi}."""
        try:
            res = self.llm.chat_text(system, prompt, temperature=temperature)
        except LLMTooLong as e:
            # chạy thật 9/10: một lượt trả lời quá dài làm hỏng CẢ đề xuất -> coi như một câu trả lời không dùng được
            return LLMResult(data={"_error": str(e)}, raw="", model=self.llm.model, seconds=0.0, prompt_tokens=0,
                             output_tokens=0)
        try:
            return replace(res, data=sigma.parse(res.raw))
        except SigmaError as e:
            try:
                again = self.llm.chat_text(system, f"{prompt}\n\nYour previous answer could not be used: {e}. Answer "
                                           "again with exactly one Sigma rule in a ```yaml block.", temperature=temperature)
            except LLMTooLong as e2:
                return replace(res, data={"_error": str(e2)})
            again = replace(again, seconds=round(res.seconds + again.seconds, 1),
                            output_tokens=res.output_tokens + again.output_tokens)
            try:
                return replace(again, data=sigma.parse(again.raw))
            except SigmaError as e2:
                return replace(again, data={"_error": str(e2)})

    def _rule_from_sigma(self, sig: dict[str, Any], rid: str, pid: str, extra_tags: list[str], domain: str,
                         known_mitre: dict[str, Any] | None = None) -> dict[str, Any]:
        """Rule Sigma -> rule của engine (điều kiện đã biên dịch) + bản Sigma chuẩn hóa ở khóa `sigma` (lưu cùng file
        rule để người duyệt đọc / xuất sang SIEM khác). known_mitre: kỹ thuật / tactic ATT&CK từ nhãn dataset, luôn
        được ghi vào rule (model hay bỏ trống hoặc điền nhầm); tag attack.* hợp lệ model đưa thêm vẫn giữ."""
        cond, _ = sigma.compile_rule(sig, domain)
        techs, tactic = sigma.attack_tags(sig.get("tags"))
        if known_mitre:
            techs = list(dict.fromkeys([*known_mitre.get("technique", []), *techs]))
            tactic = tactic or str(known_mitre.get("tactic") or "")
        level = str(sig.get("level") or "").lower()
        severity = level if level in ("low", "medium") else "medium"      # AI không được đặt high / critical
        title = str(sig.get("title") or rid)[:200]
        description = str(sig.get("description") or "").strip()[:1000]
        return {
            "id": rid, "title": title, "description": description, "severity": severity,
            "mitre": {"tactic": tactic[:60], "technique": techs[:5]},
            "tags": ["ai-generated", "sigma", *extra_tags], "type": "match", "suppress": 300,
            "condition": cond, "ai_proposal_id": pid,
            "sigma": sigma.render(sig, title=title, description=description, level=severity, techniques=techs[:5],
                                  tactic=tactic, logsource=sigma.LOGSOURCE[domain],
                                  author=f"siem-xdr AI worker ({self.llm.model}), {rid}",
                                  derived=sig.get("_derived") or []),
        }

    def propose_dataset_rule(self, key: str, missed: list, rules: list[Rule], ds: ESDataSource,
                             rejected: list[str]) -> dict[str, Any]:
        if missed[0].label.get("technique"):
            return self.propose_endpoint_rule(key, missed, rules, ds, rejected)
        items = sorted(missed, key=lambda x: str(get(x.doc, "url.original") or get(x.doc, "event.id")))
        train, test = items[0::2], items[1::2]          # tách tập: LLM chỉ thấy (một phần) tập train
        picked = diverse(train, 8, key=self.golden.variant)   # trải đều theo biến thể, biến thể đông trước
        shown = [x.doc for x in picked]
        # thống kê biến thể trên CẢ tập train (không chỉ 8 mẫu) -> rule phủ biến thể phổ biến; tập kiểm tra vẫn giữ riêng
        variants = dict(Counter(self.golden.variant(x) for x in train).most_common(15))
        web = get(shown[0], "event.category") == "web"
        domain = "web" if web else "other"
        paths = {get(d, "url.path") for d in shown}
        with_query = web and any(get(d, "url.query") for d in shown)   # payload trong query -> đối chứng với request có query
        normal_all = self.golden.normal_for("web")
        pool = [d for d in normal_all if get(d, "url.path") in paths and (get(d, "url.query") or not with_query)]
        normals = diverse(pool, 6) or diverse(normal_all, 6)
        module = get(shown[0], "event.module")
        kind = key.rsplit(":", 1)[-1]
        what = TYPES[kind].prompt if kind in TYPES else kind
        similar = self.golden.similar_sigma(shown, module, hint=what, k=8)
        refs = [sigma.reference(r) for r in similar[:3]]
        community = [r for r in similar if (r.get("logsource") or {}).get("category") == "webserver"] \
            if settings.AI_SIGMAHQ_CANDIDATES else []
        ctx = (f"Attack type: {what}. These samples come from public dataset '{key.split(':')[0]}' and no current "
               f"rule detects them ({len(missed)} events, {len(train)} of them in the training set summarized by "
               "variants). Write a GENERIC Sigma rule for this attack type that would work on any web application: "
               "do not use paths, file names or parameter names specific to the sample application. "
               "Normal samples are legitimate requests to the same application.")
        payloads = [self.golden.evidence(x) for x in picked]
        prompt = sigma_rule_prompt(ctx, domain, [sigma_view(d, domain) for d in shown],
                                   [sigma_view(d, domain) for d in normals], refs, rejected, variants=variants,
                                   payloads=payloads)
        first = self._ask_sigma(SIGMA_SYSTEM, prompt)
        normal_half = normal_all[0::2]                  # ghép vế chỉ nhìn nửa tập bình thường
        # ghép vế dựa trên payload trong URL -> chỉ áp dụng cho nhóm web (EVTX giữ câu trả lời đầu)
        final, attempts = self._refine(first, key, domain, train, normals, normal_half,
                                       app_tokens=self.golden.profile.app_tokens(),
                                       variant=self.golden.variant, what=what, community=community) \
            if web else (first, [])
        return self._finish_new_rule(final, f"gap-dataset:{key}", rules, ds, [x.doc for x in train],
                                     [x.doc for x in test], key, ["dataset-gap", kind], domain,
                                     app_tokens=self.golden.profile.app_tokens(), attempts=attempts,
                                     normal=normal_all if web else None,
                                     normal_label="request bình thường" if web else "event bình thường")

    def propose_endpoint_rule(self, key: str, missed: list, rules: list[Rule], ds: ESDataSource,
                              rejected: list[str]) -> dict[str, Any]:
        """Kỹ thuật ATT&CK trên Windows / Linux chưa rule nào bắt -> rule Sigma process_creation.
        Khác web: tập kiểm tra là các BÀI THỬ LLM chưa thấy (mỗi bài thử sinh tiến trình shell + tiến trình con gần
        trùng dòng lệnh; tách theo event thì tập kiểm tra chứa gần nguyên văn mẫu đã đưa) -> rule phải khái quát
        được kỹ thuật, không chỉ chép lệnh; tập bình thường là lệnh quản trị cùng hệ điều hành (baseline.py) và
        hoạt động nền ghi thật."""
        g = self.golden
        lab = g._inspect(missed[0])
        platform, kind = g.domain(missed[0]), key.rsplit(":", 1)[-1]
        tid = kind.split("-", 1)[1]                       # T1218 (nhóm kỹ thuật gốc) hoặc T1218.011 (kỹ thuật con)
        sub = "." in tid
        # nhóm kỹ thuật con: biến thể = chương trình chính (cùng kỹ thuật con thì g.variant giống nhau hết)
        variant = _program if sub else g.variant
        name = str(lab.get("technique_name")) if sub else str(lab["group_name"])
        train, test = split_by_test(missed, variant)
        picked = diverse(train, 8, key=variant)
        shown = [x.doc for x in picked]
        variants = dict(Counter(variant(x) for x in train).most_common(15))
        tactics = [str(t) for t in lab.get("tactics") or []]
        what = f"{name} ({tid}; tactic {', '.join(tactics) or '?'}) on {OS_NAME[platform]}"
        normal_all = g.normal_for("endpoint", platform)
        names = {str(get(d, "process.name") or "").lower() for d in shown}
        same = [d for d in normal_all if str(get(d, "process.name") or "").lower() in names]
        rest = [d for d in normal_all if not any(d is s2 for s2 in same)]
        # bình thường cùng chương trình (reg query cạnh reg save) cho LLM thấy ranh giới; còn chỗ thì chương trình khác
        normals = (diverse(same, 4, key=_proc_key) + diverse(rest, 6, key=_proc_key))[:6]
        refs = [sigma.reference(r) for r in g.similar_sigma(shown, get(shown[0], "event.module"), hint=what,
                                                            techniques=[tid], platform=platform)]
        community = g.sigmahq_for(tid, platform) if settings.AI_SIGMAHQ_CANDIDATES else []
        n_tests = len({_test_id(x) for x in missed})
        source = "recorded while running" if x_recorded(missed[0]) else "rebuilt from"
        ctx = (f"ATT&CK technique: {what}. The samples are process creation events {source} {n_tests} attack "
               f"tests of this technique ({len(missed)} events, {len(train)} of them in the training set summarized "
               "by variants); no current rule detects them. The rule is tested on held-out TESTS, so write a GENERIC "
               f"Sigma rule for this technique that would work on any {OS_NAME[platform]} host: tie each program to "
               "its distinctive arguments; do not use file names, folders, user names or hosts of the test "
               "environment (AtomicRedTeam, ExternalPayloads, files named after technique IDs, user 'art'). Normal "
               "samples are legitimate commands on the same OS; the rule must not match them.")
        prompt = sigma_rule_prompt(ctx, platform, [sigma_view(d, platform) for d in shown],
                                   [sigma_view(d, platform) for d in normals], refs, rejected, variants=variants)
        first = self._ask_sigma(SIGMA_SYSTEM, prompt)
        # tập lệnh bình thường là danh sách để chặn rule quá chung chung (vai trò như ORDINARY_URLS), không phải mẫu
        # thống kê như CSIC normal -> ghép vế đo trên CẢ tập; chỉ dùng nửa thì lượt đầu giữ `reg add`
        # (nửa kia mới có lệnh reg add hợp lệ), dừng sớm vì bắt 91% train rồi bị kiểm định loại
        lab_tokens = g.lab_tokens(platform)              # tên file / giá trị bài thử tự đặt (evilBinary, /tmp/hello)
        final, attempts = self._refine(first, key, platform, train, normals, normal_all, app_tokens=lab_tokens,
                                       variant=variant, what=what, community=community)
        return self._finish_new_rule(final, f"gap-dataset:{key}", rules, ds, [x.doc for x in train],
                                     [x.doc for x in test], key, ["dataset-gap", "endpoint", platform, kind], platform,
                                     app_tokens=lab_tokens, attempts=attempts, normal=normal_all,
                                     normal_label=f"lệnh {OS_NAME[platform]} bình thường",
                                     known_mitre={"technique": [tid], "tactic": tactics[0] if tactics else ""})

    def _refine(self, first: LLMResult, key: str, domain: str, train: list, normals: list[Doc],
                measure_normal: list[Doc], app_tokens: set[str], variant: Callable[[Any], str], what: str = "",
                community: list[dict[str, Any]] | None = None) -> tuple[LLMResult, list[dict[str, Any]]]:
        """Ghép rule Sigma từ nhiều nguồn, mỗi vế được biên dịch và đo trên tập train và tập bình thường; chỉ giữ vế bắt
        thêm được tấn công mà không khớp event bình thường nào, không gắn với ứng dụng mẫu / môi trường thử, đủ đặc trưng.
          lượt 0      câu trả lời đầu của model + vế từ rule SigmaHQ cùng kỹ thuật (community, không gọi LLM)
          lượt kiến thức  hỏi riêng các công cụ / cách làm KHÁC của kỹ thuật mà mẫu chưa có (luôn chạy, kể cả khi train
                      đã đạt): chạy thử 8/10, T1003.003 bắt 100% train ngay lượt đầu nên dừng, tập kiểm tra dùng
                      ntdsutil / vssadmin nên chỉ được 17% — mục tiêu "khớp train" không thưởng cho kiến thức
          lượt bổ sung  dồn vào MỘT biến thể còn sót nhiều nhất, prompt mới, không kèm câu trả lời cũ (model 7B chỉ chép
                      lại), cho tới khi bắt >= 80% train
        Vế an toàn nhưng chưa khớp mẫu train nào (hiểu biết của model ở lượt đầu / lượt kiến thức, rule SigmaHQ cho cách
        làm chưa có trong mẫu) vẫn được giữ, có giới hạn — đúng thứ tập kiểm tra đo. Vế bị loại được tách nhỏ / nới
        (sigma.split / relax); vế đạt được tổng quát hóa khi vẫn sạch (sigma.generalize). Mỗi vế mang nguồn
        (model / knowledge / sigmahq) để người duyệt và phép đo biết vế nào từ đâu. Tập kiểm tra không dùng ở đây."""
        if first.data.get("no_rule") or first.data.get("_error"):
            return first, []
        web = domain == "web"
        unverified: list[dict[str, Any]] = []          # vế an toàn chưa khớp train: model (lượt đầu, lượt kiến thức)
        unverified_hq: list[dict[str, Any]] = []       # ... và rule SigmaHQ
        kept: list[tuple[dict[str, Any], set[int]]] = []
        bad: list[dict[str, Any]] = []
        seen: set[str] = set()
        covered: set[int] = set()
        attempts: list[dict[str, Any]] = []
        focused: Counter = Counter()
        normal_views = [sigma_view(d, domain) for d in normals]
        args = (domain, train, measure_normal, app_tokens, seen, bad)

        def absorb(measured: list[tuple[dict[str, Any], set[int]]]) -> list[dict[str, Any]]:
            nonlocal covered
            added = []
            while measured:      # tham lam: vế bắt THÊM nhiều nhất trước, bỏ vế không bắt thêm được gì
                atom, hits = max(measured, key=lambda m: len(m[1] - covered))
                measured.remove((atom, hits))
                if hits - covered:
                    kept.append((atom, hits))
                    covered |= hits
                    added.append(atom)
            return added

        def record(rnd: int, focus: str | None, res: LLMResult | None, added: list, n_bad: int, **extra) -> None:
            recall = len(covered) / len(train) if train else 0.0
            attempts.append({"round": rnd, "focus": focus, "seconds": res.seconds if res else 0.0,
                             "kept": [sigma.detection_yaml(a) for a in added], "train_recall": round(recall, 3),
                             "rejected": [b["why"][:200] for b in bad[n_bad:]][:12], **extra})
            log.info("%s lượt %s: giữ %d vế, bắt %.0f%% tập train", key, focus or rnd, len(added), 100 * recall)

        def usable(res: LLMResult) -> bool:
            if res.data.get("_error") or res.data.get("no_rule"):
                bad.append({"detection": None, "why": "not a usable Sigma rule: "
                            + str(res.data.get("_error") or "answered no_rule")[:200]})
                return False
            return True

        # lượt 0: câu trả lời đầu + rule SigmaHQ cùng kỹ thuật
        n_bad = len(bad)
        added = absorb(self._measure_rule(first.data, *args, spare=unverified, source={"kind": "model"}))
        hq = self._community_atoms(community or [])
        added += absorb(self._measure_atoms(hq, *args, spare=unverified_hq, cap=0 if web else MAX_UNVERIFIED_SIGMAHQ,
                                            atom_cap=MAX_UNVERIFIED_SIGMAHQ_ATOMS, report=False, budget=200))
        record(0, None, first, added, n_bad, unverified=[sigma.detection_yaml(a) for a in unverified],
               sigmahq_candidates=len({id(a.get("source")) for a in hq}),
               sigmahq_unverified=[sigma.detection_yaml(a) for a in unverified_hq])
        rnd = 1
        # lượt kiến thức
        if settings.AI_KNOWLEDGE_ROUND:
            n_bad = len(bad)
            res = self._ask_sigma(SIGMA_KNOWLEDGE_SYSTEM, sigma_knowledge_prompt(
                domain, what, sorted(Counter(variant(x) for x in train), key=str)[:15],
                [sigma.atom_rule(a)["detection"] for a in [a for a, _ in kept] + unverified], normal_views),
                temperature=0.4)
            n_unv = len(unverified)
            added = absorb(self._measure_rule(res.data, *args, spare=unverified, source={"kind": "knowledge"})) \
                if usable(res) else []
            record(rnd, "knowledge", res, added, n_bad,
                   unverified=[sigma.detection_yaml(a) for a in unverified[n_unv:]])
            rnd += 1
        # lượt bổ sung cho biến thể còn sót
        for _ in range(settings.AI_REFINE_ROUNDS):
            if not train or len(covered) / len(train) >= 0.8 or len(kept) >= 15:
                break
            missed = [x for i, x in enumerate(train) if i not in covered]
            lost = Counter(variant(x) for x in missed)
            # biến thể còn sót nhiều nhất, ưu tiên biến thể chưa được hỏi riêng lần nào
            focus = min(lost, key=lambda v: (focused[v], -lost[v], v))
            focused[focus] += 1
            sample = [x for x in missed if variant(x) == focus]
            # hỏi lại cùng biến thể: tăng temperature (model 7B hay trả lời y hệt lần trước); web: đổi kiểu payload
            # luân phiên khúc URL / đúng tham số (thử nghiệm: mỗi kiểu hợp với biến thể khác nhau)
            style = "window" if focused[focus] % 2 else "param"
            chosen = diverse(sample, 8) if web else diverse(sample, 8, key=lambda x: _proc_key(x.doc))
            n_bad = len(bad)
            res = self._ask_sigma(SIGMA_REFINE_SYSTEM, sigma_refine_prompt(
                domain, focus, len(sample), [sigma_view(x.doc, domain) for x in chosen],
                [sigma.atom_rule(a)["detection"] for a in [a for a, _ in kept] + unverified], bad, normal_views,
                payloads=[self.golden.evidence(x, style) for x in chosen] if web else None),
                temperature=min(0.2 + 0.3 * (focused[focus] - 1), 0.8))
            added = absorb(self._measure_rule(res.data, *args, source={"kind": "model"})) if usable(res) else []
            record(rnd, focus, res, added, n_bad)
            rnd += 1
        final = [(a, True) for a, _ in kept] + [(a, False) for a in unverified + unverified_hq]
        if not final:
            return first, attempts
        info = []
        for a, verified in final:
            src = a.get("source") or {"kind": "model"}
            info.append({"source": src.get("kind"), "sigmahq_id": src.get("id"), "sigmahq_title": src.get("title"),
                         "verified": verified, "detection": sigma.detection_yaml(a),
                         "condition": sigma.compile_rule(sigma.atom_rule(a), domain)[0]})
        derived = list({s["id"]: s for a, _ in final if (s := a.get("source") or {}).get("kind") == "sigmahq"}.values())
        rule = {**first.data, "detection": sigma.assemble([a for a, _ in final]), "_atoms": info, "_derived": derived}
        return replace(first, data=rule), attempts

    def _community_atoms(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Vế từ rule SigmaHQ (detection lưu dạng văn bản YAML; bị cắt ở 1.500 ký tự thì bỏ). Mỗi vế mang nguồn để ghi
        công tác giả theo giấy phép DRL 1.1."""
        out: list[dict[str, Any]] = []
        for r in rules:
            try:
                det = yaml.safe_load(r.get("detection") or "")
                ats = sigma.atoms({"detection": det})
            except Exception:  # noqa: BLE001
                continue
            src = {"kind": "sigmahq", "id": r.get("id"), "title": r.get("title"), "author": r.get("author"),
                   "level": r.get("level"),
                   # rules-emerging-threats/: IOC của chiến dịch / CVE / nhóm APT cụ thể -> chỉ dùng khi khớp mẫu train
                   "emerging": not str(r.get("path") or "rules/").startswith("rules/")}
            for a in ats:
                a["source"] = src
                out.append(a)
        return out

    def _measure_rule(self, rule: dict[str, Any], domain: str, train: list, normal: list[Doc], app_tokens: set[str],
                      seen: set[str], bad: list[dict[str, Any]], spare: list[dict[str, Any]] | None = None,
                      source: dict[str, Any] | None = None) -> list[tuple[dict[str, Any], set[int]]]:
        try:
            queue = sigma.atoms(rule)
        except SigmaError as e:
            bad.append({"detection": rule.get("detection"), "why": str(e)})
            return []
        for a in queue:
            a["source"] = source or {"kind": "model"}
        return self._measure_atoms(queue, domain, train, normal, app_tokens, seen, bad, spare=spare)

    def _measure_atoms(self, queue: list[dict[str, Any]], domain: str, train: list, normal: list[Doc],
                       app_tokens: set[str], seen: set[str], bad: list[dict[str, Any]],
                       spare: list[dict[str, Any]] | None = None, cap: int | None = None,
                       atom_cap: int | None = None, report: bool = True,
                       budget: int = 24) -> list[tuple[dict[str, Any], set[int]]]:
        """Đo từng vế. Vế bị loại vì báo nhầm / quá yếu / dấu vết lab được TÁCH NHỎ (sigma.split); vế không khớp mẫu
        train nào được NỚI (sigma.relax: bỏ filter, |all -> OR) rồi đo lại phần con. spare: nơi giữ vế gốc an toàn nhưng
        chưa khớp mẫu train nào (tối đa cap vế gốc, mặc định MAX_UNVERIFIED, và atom_cap vế) — trừ khi bản nới của chính nó đã bắt được mẫu
        (khi đó model chỉ viết sai cú pháp, không phải hiểu biết riêng). report=False: không đưa lý do loại cho model
        (vế SigmaHQ)."""
        cap = MAX_UNVERIFIED if cap is None else cap        # 0 = không giữ vế chưa kiểm chứng (web + SigmaHQ)
        queue = list(queue)
        out: list[tuple[dict[str, Any], set[int]]] = []
        origin: dict[int, dict[str, Any]] = {}          # id(vế con) -> vế gốc
        via: dict[int, str] = {}                        # id(vế con) -> "split" (tập con của vế gốc) | "relax" (nới rộng)
        candidates: list[tuple[dict[str, Any], dict[str, Any], str]] = []   # (vế gốc, vế, "root" | "split")
        explained: set[int] = set()
        while queue and budget:
            atom = queue.pop(0)
            got = self._measure(atom, domain, train, normal, app_tokens, seen)
            if got is None:                      # trùng vế đã đo
                continue
            budget -= 1
            hits, nh, err = got
            root = origin.get(id(atom), atom)
            if err or nh:
                why = err or (f"matches {len(nh)} normal {'requests' if domain == 'web' else 'events'}, e.g. "
                              f"{describe(nh[0])[:150]}")
                parts = sigma.split(atom)
            elif not hits:
                # nới chỉ để sửa lỗi cú pháp của MODEL; rule SigmaHQ do người viết, nới chỉ đẻ thêm vế và đốt ngân sách đo
                # (thử 8/10: hết 80 lần đo sau ~8 rule, rule MS-settings bắt 4/8 bài thử UAC bypass không được đo tới)
                parts = [] if (atom.get("source") or {}).get("kind") == "sigmahq" else sigma.relax(atom)
                why = "matches no training event" + (
                    " (a version without the filter / with |all read as OR was tried)" if parts else "")
                # vế gốc, hoặc mảnh tách từ vế gốc (tập con của nó: vd rule SigmaHQ bỏ đúng giá trị khớp lệnh bình
                # thường) — không nhận bản NỚI (rộng hơn vế gốc, không có bằng chứng); rule chiến dịch / CVE thì không
                kind = "root" if root is atom else via.get(id(atom))
                if spare is not None and kind in ("root", "split") and not (atom.get("source") or {}).get("emerging"):
                    candidates.append((root, atom, kind))   # có thể là hiểu biết (procdump ... lsass): quyết định sau
                    why = ""
            else:
                atom, hits = self._generalize(atom, hits, domain, train, normal, app_tokens, seen)
                out.append((atom, hits))
                explained.add(id(root))
                continue
            for part in parts:
                part["source"] = atom.get("source")
                origin[id(part)] = root
                via[id(part)] = "relax" if not (err or nh) else ("split" if via.get(id(atom), "split") == "split"
                                                                  or root is atom else "relax")
            queue[:0] = parts
            if why and report:
                bad.append({"detection": sigma.atom_rule(atom)["detection"],
                            "why": why + (" (its parts were tried separately)" if parts and (err or nh) else "")})
        if spare is not None:
            # giới hạn theo SỐ VẾ GỐC (mảnh của cùng vế gốc được ghép lại khi xuất rule); vế gốc mà bản nới của chính nó
            # đã bắt được mẫu thì bỏ (model chỉ viết sai cú pháp, không phải hiểu biết riêng)
            roots = {a.get("_root") for a in spare}
            for root, atom, kind in candidates:
                if atom_cap is not None and len(spare) >= atom_cap:
                    break
                if kind == "root" and id(root) in explained:
                    continue
                rid = f"{id(self)}:{id(root)}:{len(seen)}" if "_root" not in root else root["_root"]
                root.setdefault("_root", rid)
                if root["_root"] not in roots:
                    if len(roots) >= cap:
                        continue
                    roots.add(root["_root"])
                atom["_root"] = root["_root"]
                spare.append(atom)
        return out

    def _generalize(self, atom: dict[str, Any], hits: set[int], domain: str, train: list, normal: list[Doc],
                    app_tokens: set[str], seen: set[str]) -> tuple[dict[str, Any], set[int]]:
        """Vế đã đạt -> leo dần lên bản tổng quát hơn (sigma.generalize) chừng nào còn sạch và còn bắt mọi mẫu train
        cũ; hòa thì chọn bản tổng quát (tập kiểm tra đo đúng khả năng khái quát). Không gọi LLM."""
        for _ in range(6):
            best = None
            for cand in sigma.generalize(atom):
                got = self._measure(cand, domain, train, normal, app_tokens, seen)
                if got is None:
                    continue
                h, nh, err = got
                if not err and not nh and h >= hits and (best is None or len(h) > len(best[1])):
                    cand["source"] = atom.get("source")
                    best = (cand, h)
            if best is None:
                break
            atom, hits = best
        return atom, hits

    @staticmethod
    def _measure(atom: dict[str, Any], domain: str, train: list, normal: list[Doc], app_tokens: set[str],
                 seen: set[str]) -> tuple[set[int], list[Doc], str | None] | None:
        try:
            cond, _ = sigma.compile_rule(sigma.atom_rule(atom), domain)
        except SigmaError as e:
            return set(), [], str(e)
        sig = json.dumps(cond, sort_keys=True, ensure_ascii=False)
        if sig in seen:
            return None
        seen.add(sig)
        positive = leaves_of(cond, positive_only=True)
        if domain in SIGNATURE_FIELDS and not any(c["field"].startswith(SIGNATURE_FIELDS[domain]) for c in positive):
            # mã trạng thái / phương thức / tài khoản đứng riêng không phải chữ ký (tổng quát hóa có thể rút về đó)
            return set(), [], ("no signature: a selection must test " +
                               ("the URL or User-Agent" if domain == "web" else "the program (Image) or CommandLine"))
        for c in leaves_of(cond):
            if c["op"] == "regex":
                for pat in c["value"] if isinstance(c["value"], list) else [c["value"]]:
                    if (why := regex_risk(str(pat))):
                        return set(), [], f"regex {pat!r}: {why}"
        if (tied := _app_specific(positive, app_tokens)):
            return set(), [], f"specific to the sample application or test environment ({', '.join(sorted(tied))})"
        if (wrap := lab_wrapper(cond)):
            return set(), [], (f"contains the test harness wrapper '& {{' ({wrap[0]!r}, from powershell -Command "
                               "\"& {...}\" of the test runner): match the attack command itself")
        if (weak := weak_values(cond)):
            return set(), [], (f"too short or a single common word, not a signature ({weak[0]!r}): tie the program "
                               "(Image) to its distinctive arguments in the same selection")
        if (bare := common_program_only(cond)):
            return set(), [], (f"only names a common program ({', '.join(sorted(set(bare)))}), which matches every "
                               "legitimate run: add its distinctive arguments (CommandLine) in the same selection")
        try:
            compiled = Rule.from_dict({"id": "_atom", "title": "atom", "condition": cond}).condition
        except Exception as e:  # noqa: BLE001
            return set(), [], f"invalid: {e}"
        if any(c["field"].startswith("url.") for c in positive) and (oh := ordinary_hits(compiled)):
            return set(), [], f"too generic: matches ordinary URLs such as {oh[0]}"
        return ({i for i, x in enumerate(train) if compiled.match(x.doc)},
                [d for d in normal if compiled.match(d)], None)

    def propose_own_rule(self, g: EventGroup, rules: list[Rule], ds: ESDataSource, rejected: list[str]) -> dict | None:
        module = g.key.get("event.module")
        refs = [sigma.reference(r) for r in self.golden.similar_sigma(g.samples, module)] if self.golden else []
        ctx = (f"Group of {g.count} real events ({g.key}) observed in the last {settings.AI_REPLAY_DAYS} days "
               f"that no current rule examines. Use the dotted field names of the samples in the Sigma rule.")
        res = self._ask_sigma(SIGMA_SYSTEM, sigma_rule_prompt(ctx, "other", [sigma_view(d, "other") for d in g.samples],
                                                              [], refs, rejected))
        return self._finish_new_rule(res, f"gap-own:{g.key_str}", rules, ds, g.samples, [], g.key_str,
                                     ["coverage-gap"], "other")

    def _finish_new_rule(self, res, target: str, rules: list[Rule], ds: ESDataSource, train: list[Doc],
                         test: list[Doc], key: str, tags: list[str], domain: str,
                         app_tokens: set[str] | None = None, attempts: list[dict] | None = None,
                         normal: list[Doc] | None = None, normal_label: str = "event bình thường",
                         known_mitre: dict[str, Any] | None = None) -> dict[str, Any]:
        pid = uuid.uuid4().hex[:12]
        if res.data.get("no_rule"):
            p = self._base("new_rule", target, res, f"{key}: AI không đề xuất rule")
            p.update(id=pid, status="no_action", required_approvals=0, rationale=str(res.data["no_rule"])[:2000])
            return p
        rid = self._next_ai_id(rules, ds)
        try:
            if res.data.get("_error"):
                raise SigmaError(res.data["_error"])
            rd = self._rule_from_sigma(res.data, rid, pid, tags, domain, known_mitre)
        except SigmaError as e:
            val = Validation(False, "cao", [Check("cấu trúc", False, f"rule Sigma không dùng được: {e}")], {})
            p = self._base("new_rule", target, res, f"Rule mới {rid} — rule Sigma không dùng được")
            p.update(id=pid, target_rule_id=rid, validation=val.to_dict(), risk="cao", required_approvals=1,
                     status="invalid", yaml=res.raw[:8000])
            return p
        if normal is None:
            normal = [x.doc for x in self.golden.normal] if self.golden else []
        val = validate_new_rule(rd, rules, train, test, normal, ds.replay_events(),
                                settings.AI_MAX_NEW_RULE_ALERTS_PER_DAY, app_tokens=app_tokens,
                                normal_label=normal_label)
        p = self._base("new_rule", target, res, f"Rule mới {rd['id']} — {rd['title']}")
        p.update(id=pid, target_rule_id=rd["id"], proposal=rd, sigma=rd["sigma"],
                 yaml=rule_to_yaml({k: v for k, v in rd.items() if k != "sigma"}),
                 validation=val.to_dict(), risk=val.risk, required_approvals=1,
                 status="pending" if val.passed else "invalid")
        if res.data.get("_atoms"):
            p["llm"]["atoms"] = res.data["_atoms"]
        if attempts:
            p["llm"].update(attempts=attempts, seconds=round(sum(a["seconds"] for a in attempts), 1))
            n_unv = sum(len(a.get("unverified") or []) for a in attempts)
            n_hq = sum(1 for x in res.data.get("_atoms") or [] if x["source"] == "sigmahq")
            if n_hq:
                p["history"].append({"at": now_iso(), "by": "ai-worker",
                                     "text": f"{n_hq} vế lấy từ rule SigmaHQ cùng kỹ thuật (DRL 1.1, ghi ở `related`): "
                                             + "; ".join(sorted({x['sigmahq_title'] for x in res.data['_atoms']
                                                                 if x['source'] == 'sigmahq'}))[:400]})
            p["history"].append({"at": now_iso(), "by": "ai-worker",
                                 "text": f"ghép {sum(len(a['kept']) for a in attempts)} vế Sigma từ {len(attempts)} "
                                         f"lượt LLM, chỉ giữ vế bắt được tấn công ở tập train và không khớp "
                                         f"{normal_label} nào"
                                         + (f"; thêm {n_unv} vế model viết từ hiểu biết về kỹ thuật, chưa có mẫu train "
                                            "nào khớp (xem kỹ khi duyệt)" if n_unv else "")})
        return p


def x_recorded(x) -> bool:
    """Mẫu endpoint ghi thật (Splunk, OTRF) hay dựng lại từ định nghĩa bài thử (Atomic Red Team)."""
    return x.label.get("dataset") != "atomic-red-team"
