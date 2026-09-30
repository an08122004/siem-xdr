"""Dataset công khai (datasets/processed, tạo bởi tools/convert_datasets.py) dùng cho AI worker:

  - BỘ MẪU VÀNG (golden positives): event tấn công có nhãn (CSIC 2010 anomalous, EVTX-ATTACK-SAMPLES).
    Mẫu nào rule đang bắt được thì đề xuất AI (ngoại lệ) KHÔNG được làm mất -> kiểm thử hồi quy.
  - TẬP BÌNH THƯỜNG (CSIC 2010 normal): đo báo nhầm của rule mới do AI đề xuất.
  - KHO SIGMA: tìm rule cộng đồng tương tự làm tài liệu tham khảo (RAG) khi đề xuất rule mới.

Lưu ý: event dataset được chạy OFFLINE qua bộ chuẩn hóa + rule engine, KHÔNG bơm vào index thật
(tránh lẫn dashboard và tránh SOAR ra lệnh chặn IP có trong dataset).
"""
from __future__ import annotations

import gzip
import json
import logging
import math
import os
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..detection.rules import Rule, RuleEngine
from ..pipeline.enrich import Enricher
from .attack_types import DATASET_ARTIFACTS, TYPES, WebProfile, inspect_web
from ..pipeline.normalize import Doc, get, normalize

log = logging.getLogger("ai.golden")

DEFAULT_DIR = Path(os.getenv("DATASETS_DIR", Path(__file__).resolve().parents[3] / "datasets" / "processed"))
_TOKEN = re.compile(r"[a-z][a-z0-9_]{2,}")
_ARTIFACT = re.compile("|".join(sorted(DATASET_ARTIFACTS)), re.I)
# event.module của siem-xdr -> logsource tương ứng bên Sigma (để ưu tiên rule cùng loại nguồn)
MODULE_TO_SIGMA = {
    "apache": {"category": "webserver"}, "windows": {"product": "windows"}, "sysmon": {"product": "windows"},
    "auth": {"product": "linux"}, "syslog": {"product": "linux"}, "process": {"product": "linux"},
    "iptables": {"category": "firewall"}, "pfsense": {"category": "firewall"}, "suricata": {"category": "network"},
}


@dataclass
class Labeled:
    doc: Doc
    label: dict[str, Any]


@dataclass
class PublicDatasets:
    directory: Path = DEFAULT_DIR
    max_normal: int = 10000
    attack: list[Labeled] = field(default_factory=list)       # mẫu tấn công QUAN SÁT ĐƯỢC từ nguồn log
    normal: list[Labeled] = field(default_factory=list)
    unobservable: int = 0                                     # tấn công nằm ngoài tầm nhìn (vd payload trong body POST)
    sigma: list[dict[str, Any]] = field(default_factory=list)
    _sigma_tokens: list[set[str]] = field(default_factory=list)
    _profile: WebProfile | None = None

    @classmethod
    def load(cls, directory: Path | None = None, config_dir: Path | None = None, max_normal: int = 10000) -> "PublicDatasets":
        from .. import settings
        ds = cls(directory=directory or DEFAULT_DIR, max_normal=max_normal)
        if not ds.directory.exists():
            log.warning("không có thư mục dataset %s — AI chạy không có bộ mẫu vàng", ds.directory)
            return ds
        enricher = Enricher(config_dir or settings.CONFIG_DIR)
        for name in ("csic_anomalous.jsonl.gz", "evtx.jsonl.gz", "csic_normal.jsonl.gz"):
            path = ds.directory / name
            if not path.exists():
                continue
            rows = list(_read(path))
            if name == "csic_normal.jsonl.gz" and len(rows) > max_normal:
                rows = random.Random(42).sample(rows, max_normal)   # lấy mẫu cố định -> kết quả lặp lại được
            for raw in rows:
                label = raw.pop("label", {})
                if not label.get("observable", True):
                    ds.unobservable += 1
                    continue
                doc = enricher.enrich(normalize(raw))
                (ds.normal if label.get("class") == "normal" else ds.attack).append(Labeled(doc, label))
        for x in ds.attack:
            ds.attack_type(x)
        sig = ds.directory / "sigma_rules.jsonl.gz"
        if sig.exists():
            ds.sigma = list(_read(sig))
            ds._sigma_tokens = [_tokens(" ".join([r.get("title") or "", r.get("description") or "",
                                                   json.dumps(r.get("logsource")), r.get("detection") or ""]))
                                for r in ds.sigma]
        log.info("dataset công khai: %d mẫu tấn công, %d bình thường, %d ngoài tầm nhìn, %d rule Sigma",
                 len(ds.attack), len(ds.normal), ds.unobservable, len(ds.sigma))
        return ds

    # ------------------------------------------------------------ loại tấn công
    @property
    def profile(self) -> WebProfile:
        """Hành vi bình thường của ứng dụng web trong dataset (dựng từ tập bình thường)."""
        if self._profile is None:
            self._profile = WebProfile.build(x.doc for x in self.normal if get(x.doc, "event.category") == "web")
        return self._profile

    def _inspect(self, x: Labeled) -> dict[str, Any]:
        if "attack_type" not in x.label:
            if get(x.doc, "event.category") == "web":
                m = inspect_web(x.doc, self.profile)
                x.label.update(attack_type=m.kind, variant=m.variant, evidence=m.evidence, evidence_window=m.short,
                               evidence_param=m.param)
            else:
                x.label.update(attack_type="khac", variant=str(get(x.doc, "event.action") or ""), evidence="")
        return x.label

    def attack_type(self, x: Labeled) -> str:
        """Nhóm của mẫu tấn công: tactic ATT&CK (EVTX) hoặc loại tấn công web (xem attack_types.py)."""
        if x.label.get("tactic"):
            return x.label["tactic"]
        return self._inspect(x)["attack_type"]

    def variant(self, x: Labeled) -> str:
        """Kiểu con trong nhóm (vd SQLi tautology / thoát chuỗi; thư mục bị dò); EVTX: file mẫu."""
        if x.label.get("tactic"):
            return str(x.label.get("file") or get(x.doc, "event.code") or "")
        return self._inspect(x)["variant"]

    def evidence(self, x: Labeled, style: str = "full") -> str:
        """Đoạn làm request bị nghi vấn (payload), không bị cắt như URL đầy đủ khi đưa vào prompt.
        style: "full" (khúc URL rộng quanh đoạn khớp), "window" (cắt sát đoạn khớp),
        "param" (đúng cặp tham số=giá trị chứa đoạn khớp). Kiểu nào không có thì lùi về "full"."""
        if x.label.get("tactic"):
            return ""
        lab = self._inspect(x)
        # bỏ chuỗi giữ chỗ của dataset (INJECTED_PARAM): không phải payload thật, model hay chép nguyên vào rule
        return _ARTIFACT.sub("", lab.get(f"evidence_{style}") or lab["evidence"])

    @staticmethod
    def transferable(kind: str) -> bool:
        """Loại tấn công viết được rule chữ ký dùng chung (không chỉ khớp ứng dụng mẫu của dataset)."""
        return TYPES[kind].transferable if kind in TYPES else True

    # ------------------------------------------------------------ đánh giá theo từng event
    @staticmethod
    def event_hit(rule: Rule, doc: Doc) -> bool:
        """Event có làm rule 'xét tới' không (khớp điều kiện, không bị ngoại lệ). Rule ngưỡng/chuỗi cần
        nhiều event mới bắn, nên ở mức từng event chỉ xét điều kiện (hoặc bất kỳ bước nào của chuỗi)."""
        if rule.exceptions and any(ex.match(doc) for ex in rule.exceptions):
            return False
        if rule.type == "sequence":
            return any(cond.match(doc) for cond, _ in rule.steps)
        return rule.condition.match(doc)

    def positives_for(self, rule: Rule) -> list[Labeled]:
        """Mẫu tấn công mà rule HIỆN ĐANG bắt được (bộ mẫu vàng của rule)."""
        return [x for x in self.attack if self.event_hit(rule, x.doc)]

    def normal_hits(self, rule: Rule) -> list[Labeled]:
        return [x for x in self.normal if self.event_hit(rule, x.doc)]

    # ------------------------------------------------------------ báo cáo độ phủ
    def evaluate(self, rules: list[Rule]) -> dict[str, Any]:
        match_rules = [r for r in rules if r.type == "match"]
        per_rule: dict[str, dict[str, int]] = {}
        for r in match_rules:
            per_rule[r.id] = {"attack": len(self.positives_for(r)), "normal": len(self.normal_hits(r))}
        detected = sum(1 for x in self.attack if any(self.event_hit(r, x.doc) for r in match_rules))
        false_pos = sum(1 for x in self.normal if any(self.event_hit(r, x.doc) for r in match_rules))
        by_dataset: dict[str, Counter] = defaultdict(Counter)
        for x in self.attack:
            hit = any(self.event_hit(r, x.doc) for r in match_rules)
            key = self.attack_type(x)
            by_dataset[key]["total"] += 1
            by_dataset[key]["detected"] += hit
        # EVTX: chạy đầy đủ engine theo từng file (rule ngưỡng / chuỗi cần thứ tự event)
        files: dict[str, list[Labeled]] = defaultdict(list)
        for x in self.attack:
            if x.label.get("file"):
                files[x.label["file"]].append(x)
        file_hits = {}
        for fname, items in files.items():
            eng = RuleEngine(rules)
            fired = {d.rule.id for x in items for d in eng.process(x.doc)}
            file_hits[fname] = {"tactic": items[0].label.get("tactic"), "rules": sorted(fired)}
        return {
            "attack_events": len(self.attack), "normal_events": len(self.normal), "unobservable": self.unobservable,
            "detected": detected, "false_positives": false_pos,
            "recall": detected / len(self.attack) if self.attack else None,
            "fp_rate": false_pos / len(self.normal) if self.normal else None,
            "precision": detected / (detected + false_pos) if detected + false_pos else None,
            "per_rule": per_rule, "by_group": {k: dict(v) for k, v in by_dataset.items()}, "files": file_hits,
        }

    # ------------------------------------------------------------ RAG Sigma
    def similar_sigma(self, samples: list[Doc], module: str | None, k: int = 3, hint: str = "") -> list[dict[str, Any]]:
        """Rule Sigma gần nhất theo từ khóa. `hint` (vd mô tả loại tấn công) được tính trọng số gấp đôi:
        chỉ dựa vào mẫu thì từ khóa của ứng dụng (tienda1, publico...) lấn át, kéo về rule CVE không liên quan."""
        if not self.sigma:
            return []
        q: set[str] = set()
        for d in samples[:10]:
            q |= _tokens(json.dumps(_flat(d), ensure_ascii=False))
        h = _tokens(hint)
        want = MODULE_TO_SIGMA.get(module or "", {})
        scored = []
        for r, toks in zip(self.sigma, self._sigma_tokens):
            if not toks:
                continue
            s = len(q & toks) / math.sqrt(len(q) * len(toks) or 1)
            if h:
                s += 2 * len(h & toks) / math.sqrt(len(h) * len(toks))
            ls = r.get("logsource") or {}
            if want and all(ls.get(k2) == v for k2, v in want.items()):
                s *= 2  # cùng loại nguồn log
            scored.append((s, r))
        scored.sort(key=lambda x: -x[0])
        return [r for s, r in scored[:k] if s > 0]


def _read(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


def _flat(d: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(d, dict):
        for k, v in d.items():
            if k in ("raw", "trigger_event"):
                continue
            out.update(_flat(v, f"{prefix}{k}."))
    else:
        out[prefix[:-1]] = d
    return out


def report_markdown(rep: dict[str, Any], rules: list[Rule]) -> str:
    pct = lambda x: "—" if x is None else f"{x * 100:.1f}%"  # noqa: E731
    lines = [
        "# Báo cáo độ phủ rule trên dataset công khai", "",
        "Sinh bởi `python -m siem.ai.benchmark`. Chỉ tính rule dạng `match` ở mức từng event "
        "(rule ngưỡng/chuỗi cần nhiều event liên tiếp nên không đánh giá trên request độc lập).", "",
        "| Chỉ số | Giá trị |", "|---|---|",
        f"| Mẫu tấn công quan sát được | {rep['attack_events']:,} |",
        f"| Mẫu tấn công ngoài tầm nhìn (payload trong body POST/PUT, access log không ghi) | {rep['unobservable']:,} |",
        f"| Mẫu bình thường (lấy mẫu) | {rep['normal_events']:,} |",
        f"| Phát hiện (recall trên mẫu quan sát được) | {rep['detected']:,} ({pct(rep['recall'])}) |",
        f"| Báo nhầm trên mẫu bình thường | {rep['false_positives']:,} ({pct(rep['fp_rate'])}) |",
        f"| Precision | {pct(rep['precision'])} |", "",
        "## Theo loại tấn công", "",
        "Nhóm do heuristic thô trong `siem/ai/attack_types.py` gán, chỉ để gom ứng viên cho AI. "
        "Loại *riêng ứng dụng* là bất thường của chính ứng dụng mẫu (tham số lạ, giá trị sai định dạng, "
        "đường dẫn không tồn tại): không viết được rule chữ ký dùng chung nên không giao cho AI.", "",
        "| Loại | Tổng | Phát hiện | Tỉ lệ | Giao cho AI viết rule |", "|---|---|---|---|---|",
    ]
    for k, v in sorted(rep["by_group"].items(), key=lambda kv: (not PublicDatasets.transferable(kv[0]), -kv[1]["total"])):
        name = f"{TYPES[k].label} (`{k}`)" if k in TYPES else k
        ai = "có" if PublicDatasets.transferable(k) else "không (riêng ứng dụng)"
        lines.append(f"| {name} | {v.get('total', 0):,} | {v.get('detected', 0):,} | "
                     f"{pct(v.get('detected', 0) / v['total'] if v.get('total') else None)} | {ai} |")
    titles = {r.id: r.title for r in rules}
    lines += ["", "## Theo rule (chỉ rule có kết quả)", "", "| Rule | Tên | Bắt mẫu tấn công | Báo nhầm mẫu bình thường |", "|---|---|---|---|"]
    for rid, v in sorted(rep["per_rule"].items(), key=lambda kv: -kv[1]["attack"]):
        if v["attack"] or v["normal"]:
            lines.append(f"| {rid} | {titles.get(rid, '')} | {v['attack']:,} | {v['normal']:,} |")
    if rep["files"]:
        lines += ["", "## EVTX theo file", "", "| Tactic | File | Rule bắn |", "|---|---|---|"]
        for f, v in sorted(rep["files"].items(), key=lambda kv: (kv[1]["tactic"] or "", kv[0])):
            lines.append(f"| {v['tactic']} | {f} | {', '.join(v['rules']) or '—'} |")
    return "\n".join(lines) + "\n"
