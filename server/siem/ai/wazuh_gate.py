"""Cổng Wazuh cho rule AI mới (R66): khoảng trống và kiểm định tính trên alert thật của sandbox Wazuh (sandbox.py), cây
Python chỉ còn là bộ tìm. Mỗi chu kỳ một đối tượng WazuhGate:
  - MỘT job nền (không ứng viên) cho mọi log thô của bộ mẫu vàng, nhớ kết quả trong chu kỳ;
  - MỘT job cho mỗi ứng viên, cùng mọi log thô cùng định dạng với lĩnh vực của rule (trùng thành phần với job nền), để
    "không che rule khác" so được cả mẫu tấn công rule gốc ĐANG bắt ngoài nhóm khoảng trống (Review Focus #1).
Sandbox hỏng -> SandboxError cho bên gọi: chu kỳ ghi lỗi, KHÔNG coi là "rule không bắt" hay "mọi mẫu là khoảng trống".
Đã hỏng một lần thì mọi lần gọi sau trong chu kỳ báo lại đúng lỗi đó, không giao job mới (không chờ hết giờ lần nữa).
"""
from __future__ import annotations

from ..detection.rules import Condition
from .sandbox import Hit, Sandbox, SandboxError, SandboxResult
from .sigma import SigmaError
from .validate import Check
from .wazuh_events import GENERIC, RawEvent
from .wazuh_xml import emit

CANDIDATE_BASE = 119000          # id ứng viên, chỉ tồn tại trong sandbox
DETECT_LEVEL = 7
_FMT = {"windows": "eventchannel", "linux": "siem-proc", "web": "apache"}      # lĩnh vực rule -> định dạng log thô


def detections(hits: list[Hit]) -> set[int]:
    """Rule Wazuh được coi là PHÁT HIỆN: level >= DETECT_LEVEL và không nằm trong GENERIC (khớp theo cấu trúc)."""
    return {h.rule_id for h in hits if h.level >= DETECT_LEVEL and str(h.rule_id) not in GENERIC}


class WazuhGate:
    def __init__(self, sandbox: Sandbox, raw: dict[int, RawEvent]):
        self.sandbox, self.raw = sandbox, raw
        self._base: dict[int, list[Hit]] | None = None        # ident -> alert của job nền
        self._error: SandboxError | None = None

    def _run(self, events: list[RawEvent], candidate_xml: str | None = None) -> SandboxResult:
        if self._error:
            raise self._error
        try:
            return self.sandbox.run(events, candidate_xml)
        except SandboxError as e:
            self._error = e
            raise

    def baseline(self, docs: list[dict]) -> dict[int, list[Hit]]:
        """Alert Wazuh của từng doc (khóa id(doc)) khi không có ứng viên. Doc không có log thô thì không có khóa."""
        if self._base is None:
            res = self._run(sorted(self.raw.values(), key=lambda e: e.ident))
            if res.load_error:             # không có ứng viên mà ruleset không nạp được: lỗi hạ tầng, không phải của rule
                self._error = SandboxError(f"ruleset Wazuh hiện tại không nạp được trong sandbox: {res.load_error}")
                raise self._error
            self._base = res.hits
        return {id(d): self._base.get(self.raw[id(d)].ident, []) for d in docs if id(d) in self.raw}

    def gaps(self, docs: list[dict]) -> list[dict]:
        """Doc Wazuh chưa phát hiện. Doc không dựng được log thô thì không đo được: không tính là khoảng trống."""
        base = self.baseline(docs)
        return [d for d in docs if id(d) in base and not detections(base[id(d)])]

    def check(self, tree: dict, *, domain: str, level: int, title: str, techniques: list[str], train: list[dict],
              test: list[dict], normal: list[dict]) -> tuple[list[Check], dict]:
        try:
            em = emit(tree, domain=domain, first_id=CANDIDATE_BASE, level=level, code="AI-CAND", title=title,
                      techniques=techniques, groups=["siem", "ai"], shadow_since=None)
        except SigmaError as e:
            return [Check("Wazuh nạp được rule", False, f"không dịch được sang rule Wazuh XML: {e}")], {}
        m: dict = {"wazuh_rules": len(em.ids)}
        lacking = [d for d in test + normal if id(d) not in self.raw]
        if lacking:
            return [Check("có log thô", False, f"{len(lacking)}/{len(test) + len(normal)} mẫu kiểm tra / bình thường "
                          "không dựng được log thô để bơm vào Wazuh")], m
        self.baseline([])
        mine = {self.raw[id(d)].ident for d in train + test + normal if id(d) in self.raw}
        events = sorted((e for e in self.raw.values() if e.fmt == _FMT[domain] or e.ident in mine), key=lambda e: e.ident)
        res = self._run(events, f'<group name="siem,ai,ai_candidate,">\n{em.xml}</group>\n')
        m.update(wazuh_events=len(events), wazuh_seconds=res.seconds)
        if res.load_error:
            return [Check("Wazuh nạp được rule", False, f"Wazuh không nạp được rule ứng viên: {res.load_error[:800]}")], m
        ids = set(em.ids)
        checks = [Check("Wazuh nạp được rule", True, f"{len(ids)} rule (id {em.ids[0]}–{em.ids[-1]}), "
                        f"{len(events)} event, {res.seconds:g} giây"),
                  Check("có log thô", True, f"đủ log thô cho {len(test)} mẫu kiểm tra và {len(normal)} mẫu bình thường")]

        def fired(d: dict) -> bool:
            return any(h.rule_id in ids for h in res.hits.get(self.raw[id(d)].ident, []))

        hit = sum(map(fired, test))
        recall = hit / len(test) if test else 0.0
        m.update(wazuh_test_total=len(test), wazuh_test_detected=hit, wazuh_test_recall=round(recall, 3))
        checks.append(Check("bắt mẫu nghi vấn (Wazuh)", recall >= 0.3,
                            f"alert Wazuh cho {hit}/{len(test)} mẫu kiểm tra ({recall:.0%}, cần ≥ 30%)"))
        nh = sum(map(fired, normal))
        fpr = nh / len(normal) if normal else 0.0
        m.update(wazuh_normal_total=len(normal), wazuh_normal_hits=nh, wazuh_fp_rate=round(fpr, 5))
        checks.append(Check("báo nhầm (Wazuh)", fpr <= 0.001,
                            f"alert Wazuh cho {nh}/{len(normal)} mẫu bình thường ({fpr:.2%}, tối đa 0,1%)"))
        # rule ứng viên thắng rule gốc cùng cha thì cắt cây con: event đang có alert phát hiện mà sang job này thì mất
        lost: dict[int, set[int]] = {}
        for e in events:
            if (gone := detections(self._base.get(e.ident, [])) - {h.rule_id for h in res.hits.get(e.ident, [])}):
                lost[e.ident] = gone
        m["wazuh_stolen"] = len(lost)
        rules_lost = sorted({r for g in lost.values() for r in g})
        checks.append(Check("không che rule khác", not lost, "không event nào mất alert của rule Wazuh đang có" if not lost
                            else f"{len(lost)} event mất alert của rule {', '.join(map(str, rules_lost[:10]))} "
                                 "(rule ứng viên thắng rule gốc cùng cha)"))
        cond = Condition(tree)
        both = [d for d in train + test + normal if id(d) in self.raw]
        py_only = sum(1 for d in both if cond.match(d) and not fired(d))
        wz_only = sum(1 for d in both if fired(d) and not cond.match(d))
        m.update(wazuh_python_only=py_only, wazuh_wazuh_only=wz_only)
        checks.append(Check("khớp Python", not (py_only or wz_only),
                            f"trên {len(both)} mẫu: {py_only} mẫu chỉ cây Python khớp, {wz_only} mẫu chỉ Wazuh báo"
                            + (" (thường do trường vắng mặt kết hợp phủ định)" if py_only else ""), blocking=False))
        return checks, m
