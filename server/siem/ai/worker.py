"""AI worker: mỗi chu kỳ tìm chỗ cần cải thiện rule -> hỏi LLM -> kiểm định -> lưu ĐỀ XUẤT chờ duyệt.

Ba nguồn ứng viên:
  1. exception   — rule có nhiều alert bị analyst đánh dấu false positive (nhãn thật từ case / console)
  2. gap-dataset — mẫu tấn công trong dataset công khai mà chưa rule nào bắt, gom theo LOẠI tấn công
                   (attack_types.py); tách tập đưa cho LLM / tập kiểm tra
  3. gap-own     — nhóm event thật (module/category/action) chưa có rule nào xem xét
Worker KHÔNG ghi file rule, KHÔNG có quyền sửa gì ngoài index ai-*.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .. import settings
from ..detection.rules import Rule, load_rules
from ..pipeline.normalize import Doc, get
from .attack_types import TYPES
from .dataset import ESDataSource, EventGroup
from .golden import PublicDatasets
from .llm import LLMError, OllamaClient
from .prompts import (EXCEPTION_SCHEMA, EXCEPTION_SYSTEM, NEW_RULE_SCHEMA, NEW_RULE_SYSTEM, exception_prompt,
                      new_rule_prompt, rule_to_yaml, sigma_brief)
from .validate import build_condition, scope_match, validate_exception, validate_new_rule

log = logging.getLogger("ai.worker")
OPEN = ["pending", "approved"]
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generator_id(model: str) -> str:
    """Dấu vân tay của model + system prompt đang dùng, ghi vào mỗi đề xuất."""
    return hashlib.sha1("\n".join([model, EXCEPTION_SYSTEM, NEW_RULE_SYSTEM]).encode()).hexdigest()[:10]


def diverse(docs: list[Doc], k: int) -> list[Doc]:
    """Chọn k mẫu trải đều theo url.path (lần lượt mỗi đường dẫn 1 mẫu) để LLM thấy nhiều biến thể,
    thay vì k mẫu liền nhau cùng một đường dẫn. Tất định (không ngẫu nhiên)."""
    by_path: dict[str, list[Doc]] = defaultdict(list)
    for d in docs:
        by_path[str(get(d, "url.path") or get(d, "event.action") or "")].append(d)
    queues = [by_path[p] for p in sorted(by_path)]
    out: list[Doc] = []
    i = 0
    while len(out) < k and any(i < len(q) for q in queues):
        out.extend(q[i] for q in queues if i < len(q))
        i += 1
    return out[:k]


def rule_yaml(rule: Rule) -> str:
    """Tìm lại YAML gốc của rule để đưa cho LLM (RAG: đúng rule cần tinh chỉnh)."""
    path = settings.RULES_DIR / rule.source_file if rule.source_file else None
    if path and path.exists():
        text = path.read_text(encoding="utf-8")
        m = re.search(rf"^- id: {re.escape(rule.id)}\n(?:(?!^- id: ).*\n?)*", text, re.M)
        if m:
            return m.group(0)
    return f"- id: {rule.id}\n  title: {rule.title}\n  type: {rule.type}\n"


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
        open_targets = {p["target"] for p in history if p.get("status") in OPEN}
        rejected: dict[str, list[str]] = defaultdict(list)
        recent_closed = set()
        gen = generator_id(self.llm.model)
        for p in history:
            st = p.get("status")
            # người từ chối / gỡ -> chặn 30 ngày; kiểm định tự động loại -> chỉ chặn khi CÙNG model + prompt
            # (đổi model hoặc sửa prompt thì thử lại ngay, không phải chờ hết 30 ngày)
            if st in ("rejected", "rolled_back") or \
                    (st in ("invalid", "no_action") and (p.get("llm") or {}).get("generator") == gen):
                recent_closed.add(p["target"])
            if st in ("rejected", "rolled_back") and p.get("reject_reason"):
                rejected[p["target"]].append(p["reject_reason"])
        summary = {"started_at": now_iso(), "requested_by": requested_by, "model": self.llm.model,
                   "created": [], "skipped": [], "errors": []}
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
            "rationale": str(llm_res.data.get("rationale", ""))[:2000],
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
        """Mẫu tấn công dataset chưa rule match nào bắt, gom theo loại tấn công (web) hoặc tactic (EVTX).
        Trả về cả nhóm riêng ứng dụng (không giao cho AI) để ghi vào tóm tắt chu kỳ."""
        match_rules = [r for r in rules if r.type == "match"]
        groups: dict[str, list] = defaultdict(list)
        for x in self.golden.attack:
            if not any(self.golden.event_hit(r, x.doc) for r in match_rules):
                groups[f"{x.label.get('dataset')}:{self.golden.attack_type(x)}"].append(x)
        return sorted(((k, v) for k, v in groups.items() if len(v) >= 10), key=lambda kv: -len(kv[1]))

    def _next_ai_id(self, rules: list[Rule], ds: ESDataSource) -> str:
        nums = [int(m.group(1)) for rid in [r.id for r in rules] + [
            (p.get("proposal") or {}).get("id", "") for p in ds.proposals(since="now-3650d", size=1000)]
            if (m := re.match(r"AI-(\d+)$", str(rid)))]
        return f"AI-{max(nums, default=0) + 1:03d}"

    def _rule_from_llm(self, data: dict[str, Any], rid: str, pid: str, extra_tags: list[str]) -> dict[str, Any]:
        return {
            "id": rid, "title": str(data.get("title") or rid)[:200],
            "description": str(data.get("description") or "")[:1000],
            "severity": data.get("severity") if data.get("severity") in ("low", "medium") else "medium",
            "mitre": {"tactic": str(data.get("mitre_tactic") or "")[:60],
                      # model hay điền tên tự do ("SQLi", "OS Command") -> chỉ giữ ID ATT&CK thật
                      "technique": [t for t in (str(x).strip().upper() for x in data.get("mitre_technique") or [])
                                    if MITRE_ID.match(t)][:5]},
            "tags": ["ai-generated", *extra_tags], "type": "match", "suppress": 300,
            "condition": build_condition(data.get("match", "all"), data.get("clauses") or []),
            "ai_proposal_id": pid,
        }

    def propose_dataset_rule(self, key: str, missed: list, rules: list[Rule], ds: ESDataSource,
                             rejected: list[str]) -> dict[str, Any]:
        items = sorted(missed, key=lambda x: str(get(x.doc, "url.original") or get(x.doc, "event.id")))
        train, test = items[0::2], items[1::2]          # tách tập: LLM chỉ thấy (một phần) tập train
        shown = diverse([x.doc for x in train], 8)
        paths = {get(d, "url.path") for d in shown}
        normals = diverse([x.doc for x in self.golden.normal if get(x.doc, "url.path") in paths], 6) or \
            diverse([x.doc for x in self.golden.normal], 6)
        module = get(shown[0], "event.module")
        sigma = [sigma_brief(r) for r in self.golden.similar_sigma(shown, module)]
        kind = key.rsplit(":", 1)[-1]
        what = TYPES[kind].prompt if kind in TYPES else kind
        ctx = (f"Attack type: {what}. These samples come from public dataset '{key.split(':')[0]}' and no current "
               f"rule detects them ({len(missed)} events). Write a GENERIC signature for this attack type that "
               "would work on any web application: do not use paths, file names or parameter names specific to the "
               "sample application. Normal samples are legitimate requests to the same application.")
        res = self.llm.chat_json(NEW_RULE_SYSTEM, new_rule_prompt(ctx, shown, normals, sigma, rejected), NEW_RULE_SCHEMA)
        return self._finish_new_rule(res, f"gap-dataset:{key}", rules, ds, [x.doc for x in train],
                                     [x.doc for x in test], key, ["dataset-gap", kind],
                                     app_tokens=self.golden.profile.app_tokens())

    def propose_own_rule(self, g: EventGroup, rules: list[Rule], ds: ESDataSource, rejected: list[str]) -> dict | None:
        module = g.key.get("event.module")
        sigma = [sigma_brief(r) for r in self.golden.similar_sigma(g.samples, module)] if self.golden else []
        ctx = (f"Group of {g.count} real events ({g.key}) observed in the last {settings.AI_REPLAY_DAYS} days "
               f"that no current rule examines.")
        res = self.llm.chat_json(NEW_RULE_SYSTEM, new_rule_prompt(ctx, g.samples, [], sigma, rejected), NEW_RULE_SCHEMA)
        if not res.data.get("propose"):
            p = self._base("new_rule", f"gap-own:{g.key_str}", res, f"Nhóm event {g.key_str}: AI không đề xuất rule")
            p.update(status="no_action", required_approvals=0)
            return p
        return self._finish_new_rule(res, f"gap-own:{g.key_str}", rules, ds, g.samples, [], g.key_str, ["coverage-gap"])

    def _finish_new_rule(self, res, target: str, rules: list[Rule], ds: ESDataSource, train: list[Doc],
                         test: list[Doc], key: str, tags: list[str],
                         app_tokens: set[str] | None = None) -> dict[str, Any]:
        pid = uuid.uuid4().hex[:12]
        if res.data.get("propose") is False:
            p = self._base("new_rule", target, res, f"{key}: AI không đề xuất rule")
            p.update(id=pid, status="no_action", required_approvals=0)
            return p
        rd = self._rule_from_llm(res.data, self._next_ai_id(rules, ds), pid, tags)
        normal = [x.doc for x in self.golden.normal] if self.golden else []
        val = validate_new_rule(rd, rules, train, test, normal, ds.replay_events(),
                                settings.AI_MAX_NEW_RULE_ALERTS_PER_DAY, app_tokens=app_tokens)
        p = self._base("new_rule", target, res, f"Rule mới {rd['id']} — {rd['title']}")
        p.update(id=pid, target_rule_id=rd["id"], proposal=rd, yaml=rule_to_yaml(rd), validation=val.to_dict(),
                 risk=val.risk, required_approvals=1, status="pending" if val.passed else "invalid")
        return p
