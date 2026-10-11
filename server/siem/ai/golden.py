"""Dataset công khai (datasets/processed, tạo bởi tools/convert_datasets.py) dùng cho AI worker:

  - BỘ MẪU VÀNG (golden positives): event tấn công có nhãn — web (CSIC 2010 anomalous) và ENDPOINT
    (Atomic Red Team: lệnh tấn công Windows / Linux theo kỹ thuật ATT&CK; EVTX-ATTACK-SAMPLES nếu có).
    Mẫu nào rule đang bắt được thì đề xuất AI (ngoại lệ) KHÔNG được làm mất -> kiểm thử hồi quy.
  - TẬP BÌNH THƯỜNG: request web (CSIC 2010 normal) + lệnh quản trị / hệ thống thông thường của Windows và Linux
    (baseline.py) -> đo báo nhầm của rule mới do AI đề xuất, theo đúng lĩnh vực của rule.
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
from .baseline import ordinary_processes
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
ENDPOINT_DATASETS = {"atomic-red-team", "evtx-attack-samples", "splunk-attack-data", "otrf"}
# lệnh tự soạn + hoạt động nền ghi thật (Splunk atomic_red_team, và nền lặp lại trong mọi bộ đo theo bộ)
ENDPOINT_NORMAL = {"baseline-endpoint", "splunk-background", "scenario-background"}
# dấu vết công cụ chạy bài thử trong log nền (Invoke-AtomicTest kiểm tra điều kiện, Ansible, máy Attack Range...)
LAB_TRACE = re.compile(r"atomicredteam|invoke-atomictest|externalpayloads|ansible|\$json_raw|become-success|attackrange|"
                       r"\bart\b|\bt1\d{3}", re.I)
BACKGROUND_MIN_TECHNIQUES = 3
SOURCE_NAME = {"atomic-red-team": "dựng lại từ Atomic Red Team", "splunk-attack-data": "log ghi thật (Splunk)",
               "evtx-attack-samples": "EVTX ghi thật"}
OS_NAME = {"windows": "Windows", "linux": "Linux"}


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
    # log ghi thật chỉ biết CẢ BỘ thuộc kỹ thuật nào (Splunk ngoài atomic_red_team, OTRF): đo theo bộ, không dùng từng event
    scenarios: list[Labeled] = field(default_factory=list)
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
        for name in ("csic_anomalous.jsonl.gz", "atomic.jsonl.gz", "realdata_attack.jsonl.gz", "evtx.jsonl.gz",
                     "csic_normal.jsonl.gz", "realdata_normal.jsonl.gz"):
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
        if any(x.label.get("dataset") in ENDPOINT_DATASETS for x in ds.attack):
            # endpoint không có tập bình thường công khai -> dùng lệnh quản trị / hệ thống tự soạn (baseline.py)
            for platform in ("windows", "linux"):
                ds.normal += [Labeled(enricher.enrich(d), {"dataset": "baseline-endpoint", "class": "normal",
                                                           "platform": platform}) for d in ordinary_processes(platform)]
        for x in ds.attack:
            ds.attack_type(x)
        scn = ds.directory / "realdata_scenario.jsonl.gz"
        if scn.exists():
            for raw in _read(scn):
                label = raw.pop("label", {})
                ds.scenarios.append(Labeled(enricher.enrich(normalize(raw)), label))
        ds.normal += scenario_background(ds.scenarios, ds.attack)
        sig = ds.directory / "sigma_rules.jsonl.gz"
        if sig.exists():
            ds.sigma = list(_read(sig))
            ds._sigma_tokens = [_tokens(" ".join([r.get("title") or "", r.get("description") or "",
                                                   json.dumps(r.get("logsource")), r.get("detection") or ""]))
                                for r in ds.sigma]
        n_end = sum(x.label.get("dataset") in ENDPOINT_DATASETS for x in ds.attack)
        log.info("dataset công khai: %d mẫu tấn công (%d web, %d endpoint), %d bình thường, %d ngoài tầm nhìn, "
                 "%d tiến trình theo bộ, %d rule Sigma", len(ds.attack), len(ds.attack) - n_end, n_end, len(ds.normal),
                 ds.unobservable, len(ds.scenarios), len(ds.sigma))
        return ds

    # ------------------------------------------------------------ lĩnh vực
    @staticmethod
    def is_endpoint(x: Labeled) -> bool:
        return x.label.get("dataset") in ENDPOINT_DATASETS

    @staticmethod
    def domain(x: Labeled) -> str:
        """web / windows / linux — để gom nhóm, chọn tập bình thường và xếp lượt cho AI."""
        if x.label.get("platform"):
            return x.label["platform"]
        return "windows" if x.label.get("dataset") == "evtx-attack-samples" else "web"

    def normal_for(self, domain: str, platform: str | None = None) -> list[Doc]:
        """Tập bình thường cùng lĩnh vực với rule: 'web' (CSIC normal) hoặc 'endpoint' (lệnh thông thường,
        lọc theo hệ điều hành nếu có). Đo rule endpoint trên request web thì luôn 0 báo nhầm — vô nghĩa."""
        if domain == "web":
            return [x.doc for x in self.normal if x.label.get("dataset") not in ENDPOINT_NORMAL]
        return [x.doc for x in self.normal if x.label.get("dataset") in ENDPOINT_NORMAL
                and (platform is None or x.label.get("platform") == platform)]

    # ------------------------------------------------------------ loại tấn công
    @property
    def profile(self) -> WebProfile:
        """Hành vi bình thường của ứng dụng web trong dataset (dựng từ tập bình thường)."""
        if self._profile is None:
            self._profile = WebProfile.build(x.doc for x in self.normal if get(x.doc, "event.category") == "web")
        return self._profile

    def _inspect(self, x: Labeled) -> dict[str, Any]:
        if "attack_type" not in x.label:
            if x.label.get("technique"):
                # endpoint (Atomic Red Team): nhóm = kỹ thuật ATT&CK gốc theo hệ điều hành (T1003 Windows khác hẳn
                # T1003 Linux); biến thể = kỹ thuật con (LSASS / SAM / NTDS...), không có thì chương trình chính
                # của bài thử (reg.exe, powershell Set-ItemProperty...). Biến thể theo tên bài thử thì mỗi biến thể chỉ
                # 1 bài thử -> lượt bổ sung chỉ cho model xem 1 lệnh và nó chép nguyên văn (chạy thật T1112)
                tid, name = str(x.label["technique"]), str(x.label.get("technique_name") or "")
                base = tid.split(".")[0]
                variant = (f"{tid} {name.split(': ', 1)[-1]}" if "." in tid
                           else str(x.label.get("program") or x.label.get("test") or tid))
                x.label.update(attack_type=f"{x.label.get('platform')}-{base}", variant=variant[:80],
                               evidence=str(get(x.doc, "process.command_line") or ""),
                               technique_base=base, group_name=name.split(": ", 1)[0])
            elif get(x.doc, "event.category") == "web":
                m = inspect_web(x.doc, self.profile)
                x.label.update(attack_type=m.kind, variant=m.variant, evidence=m.evidence, evidence_window=m.short,
                               evidence_param=m.param)
            else:
                x.label.update(attack_type="khac", variant=str(get(x.doc, "event.action") or ""), evidence="")
        return x.label

    def attack_type(self, x: Labeled) -> str:
        """Nhóm của mẫu tấn công: loại tấn công web (attack_types.py), kỹ thuật ATT&CK theo hệ điều hành
        (Atomic Red Team, vd windows-T1003) hoặc tactic (EVTX)."""
        if x.label.get("tactic"):
            return x.label["tactic"]
        return self._inspect(x)["attack_type"]

    def variant(self, x: Labeled) -> str:
        """Kiểu con trong nhóm (vd SQLi tautology / thoát chuỗi; thư mục bị dò); EVTX: file mẫu."""
        if x.label.get("tactic"):
            return str(x.label.get("file") or get(x.doc, "event.code") or "")
        return self._inspect(x)["variant"]

    def evidence(self, x: Labeled, style: str = "full") -> str:
        """Đoạn làm event bị nghi vấn (payload), không bị cắt như URL đầy đủ khi đưa vào prompt.
        Web — style: "full" (khúc URL rộng quanh đoạn khớp), "window" (cắt sát đoạn khớp),
        "param" (đúng cặp tham số=giá trị chứa đoạn khớp). Kiểu nào không có thì lùi về "full".
        Endpoint: dòng lệnh của tiến trình."""
        if x.label.get("tactic"):
            return ""
        if x.label.get("technique"):
            return self._inspect(x)["evidence"]
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
        caught = [any(self.event_hit(r, x.doc) for r in match_rules) for x in self.attack]
        detected = sum(caught)
        false_pos = sum(1 for x in self.normal if any(self.event_hit(r, x.doc) for r in match_rules))
        by_dataset: dict[str, Counter] = defaultdict(Counter)
        meta: dict[str, dict[str, Any]] = {}
        tests: dict[str, set[str]] = defaultdict(set)
        tests_hit: dict[str, set[str]] = defaultdict(set)
        for x, hit in zip(self.attack, caught):
            key = self.attack_type(x)
            by_dataset[key]["total"] += 1
            by_dataset[key]["detected"] += hit
            meta.setdefault(key, {"domain": self.domain(x), "name": x.label.get("group_name") or "",
                                  "technique": x.label.get("technique_base") or ""})
            if x.label.get("guid"):                         # Atomic Red Team: đếm cả theo bài thử
                tests[key].add(x.label["guid"])
                if hit:
                    tests_hit[key].add(x.label["guid"])
        domains: dict[str, dict[str, Any]] = {}
        sources = sorted({str(x.label.get("dataset")) for x in self.attack})
        for dom in ("web", "windows", "linux"):
            for src in [None, *sources] if dom != "web" else [None]:
                idx = [i for i, x in enumerate(self.attack) if self.domain(x) == dom
                       and (src is None or x.label.get("dataset") == src)]
                if not idx or (src and len(idx) == len([x for x in self.attack if self.domain(x) == dom])):
                    continue                       # nguồn duy nhất của lĩnh vực: đã có ở dòng tổng
                normal = self.normal_for("web") if dom == "web" else self.normal_for("endpoint", dom)
                fp_docs = [d for d in normal if any(self.event_hit(r, d) for r in match_rules)] if src is None else []
                groups = {self.attack_type(self.attack[i]) for i in idx}
                domains[dom if src is None else f"{dom}/{src}"] = {
                    "domain": dom, "source": src,
                    "attack": len(idx), "detected": sum(caught[i] for i in idx),
                    "groups": len(groups),
                    "groups_detected": len({self.attack_type(self.attack[i]) for i in idx if caught[i]}),
                    "normal": len(normal), "false_positives": len(fp_docs),
                    "fp_examples": [{"rules": [r.id for r in match_rules if self.event_hit(r, d)],
                                     "event": str(get(d, "process.command_line") or get(d, "url.decoded") or "")[:160]}
                                    for d in fp_docs[:10]],
                }
        scenario = self.evaluate_scenarios(match_rules)
        # EVTX: chạy đầy đủ engine theo từng file (rule ngưỡng / chuỗi cần thứ tự event)
        files: dict[str, list[Labeled]] = defaultdict(list)
        for x in self.attack:
            if x.label.get("file") and x.label.get("dataset") == "evtx-attack-samples":
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
            "per_rule": per_rule, "files": file_hits, "domains": domains, "scenario": scenario,
            "by_group": {k: {"total": v["total"], "detected": v["detected"], **meta[k],
                             **({"tests": len(tests[k]), "tests_detected": len(tests_hit[k])} if tests[k] else {})}
                         for k, v in by_dataset.items()},
        }

    def evaluate_scenarios(self, match_rules: list[Rule]) -> dict[str, Any]:
        """Đo theo BỘ: một bộ log (file) tính là bị phát hiện khi rule bắn trên ít nhất một tiến trình của nó."""
        files: dict[str, list[Labeled]] = defaultdict(list)
        for x in self.scenarios:
            files[x.label.get("file", "")].append(x)
        out: dict[str, Any] = {}
        for dom in ("windows", "linux"):
            for src in ("splunk-attack-data", "otrf"):
                fs = {f: xs for f, xs in files.items() if xs[0].label.get("platform") == dom
                      and xs[0].label.get("dataset") == src}
                if not fs:
                    continue
                hit = {f: sorted({r.id for x in xs for r in match_rules if self.event_hit(r, x.doc)}) for f, xs in fs.items()}
                techs = {xs[0].label.get("technique") for xs in fs.values()}
                techs_hit = {fs[f][0].label.get("technique") for f, h in hit.items() if h}
                out[f"{dom}/{src}"] = {"files": len(fs), "files_detected": sum(bool(h) for h in hit.values()),
                                       "events": sum(len(xs) for xs in fs.values()),
                                       "techniques": len(techs), "techniques_detected": len(techs_hit)}
        return out

    # ------------------------------------------------------------ RAG Sigma
    def sigmahq_for(self, technique: str, platform: str, limit: int = 40) -> list[dict[str, Any]]:
        """Rule SigmaHQ process_creation cùng hệ điều hành gắn đúng kỹ thuật, làm vế ứng viên (worker._refine). Nhóm kỹ
        thuật con (T1003.003): rule gắn đúng kỹ thuật con, rồi rule chỉ gắn kỹ thuật gốc; KHÔNG lấy rule của kỹ thuật
        con khác (T1003.001 LSASS không thuộc nhóm NTDS). Nhóm kỹ thuật gốc: mọi kỹ thuật con. Ưu tiên rule phát hiện
        CHUNG (thư mục rules/ của SigmaHQ) trước rule chiến dịch / CVE / nhóm APT (rules-emerging-threats/), rồi theo
        status. Không xếp theo level: thử 8/10, ưu tiên critical / high chọn toàn IOC của APT29, NotPetya, Ryuk...
        Mốc 9.5 AI-README: các rule này cộng lại đạt >= 30% tập kiểm tra ở 6/14 nhóm."""
        tid = technique.lower()
        parent = tid.split(".")[0]
        level = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        status = {"stable": 0, "test": 1, "experimental": 2}
        scored = []
        for r in self.sigma:
            ls = r.get("logsource") or {}
            if ls.get("category") != "process_creation" or ls.get("product") != platform:
                continue
            tags = {str(t).lower().removeprefix("attack.") for t in r.get("tags") or []}
            subs = {t for t in tags if t.startswith(parent + ".")}
            if tid in tags:
                prio = 0
            elif "." in tid and parent in tags and not subs:
                prio = 1
            elif "." not in tid and subs:
                prio = 1
            else:
                continue
            generic = 0 if str(r.get("path") or "rules/").startswith("rules/") else 1
            scored.append(((prio, generic, status.get(r.get("status"), 3), level.get(r.get("level"), 5)), r))
        scored.sort(key=lambda x: x[0])
        return [r for _, r in scored[:limit]]

    def similar_sigma(self, samples: list[Doc], module: str | None, k: int = 3, hint: str = "",
                      techniques: list[str] | None = None, platform: str | None = None) -> list[dict[str, Any]]:
        """Rule Sigma gần nhất theo từ khóa. `hint` (vd mô tả loại tấn công) được tính trọng số gấp đôi:
        chỉ dựa vào mẫu thì từ khóa của ứng dụng (tienda1, publico...) lấn át, kéo về rule CVE không liên quan.
        Endpoint: rule Sigma gắn đúng kỹ thuật ATT&CK (tag attack.t1003...) và cùng loại nguồn
        process_creation của cùng hệ điều hành được ưu tiên mạnh."""
        if not self.sigma:
            return []
        tech = {t.lower() for t in techniques or []}
        q: set[str] = set()
        for d in samples[:10]:
            q |= _tokens(json.dumps(_flat(d), ensure_ascii=False))
        h = _tokens(hint)
        want = ({"category": "process_creation", "product": platform} if platform
                else MODULE_TO_SIGMA.get(module or "", {}))
        scored = []
        for r, toks in zip(self.sigma, self._sigma_tokens):
            if not toks:
                continue
            s = len(q & toks) / math.sqrt(len(q) * len(toks) or 1)
            if h:
                s += 2 * len(h & toks) / math.sqrt(len(h) * len(toks))
            ls = r.get("logsource") or {}
            if tech and any(str(t).lower().removeprefix("attack.").split(".")[0] in tech or
                            str(t).lower().removeprefix("attack.") in tech for t in r.get("tags") or []):
                s += 1.5  # cùng kỹ thuật ATT&CK
            if want and all(ls.get(k2) == v for k2, v in want.items()):
                s *= 2  # cùng loại nguồn log
            scored.append((s, r))
        scored.sort(key=lambda x: -x[0])
        return [r for s, r in scored[:k] if s > 0]


def _norm_cmd(cmd: Any) -> str:
    s = str(cmd or "").lower()
    s = re.sub(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<guid>", s)
    s = re.sub(r"\b0x[0-9a-f]+\b|\b\d+\b", "#", s)
    return re.sub(r"\s+", " ", s).strip()


def scenario_background(scenarios: list[Labeled], attack: list[Labeled],
                        min_techniques: int = BACKGROUND_MIN_TECHNIQUES) -> list[Labeled]:
    """Hoạt động nền ghi thật lấy từ các bộ đo theo bộ (Splunk / OTRF): dòng lệnh (đã thay số, GUID) lặp lại trong bộ của
    >= min_techniques kỹ thuật khác nhau là tiếng ồn của máy (dịch vụ, agent), không phải tấn công của riêng bộ nào. Bỏ
    dòng mang dấu vết công cụ thử (Invoke-AtomicTest kiểm tra điều kiện lặp ở nhiều bộ) và dòng trùng mẫu tấn công đã biết.
    Đo 8/10: thêm khoảng 400 tiến trình Windows, 50 Linux (mục 9.8 AI-README)."""
    seen: dict[tuple[str, str], set] = defaultdict(set)
    first: dict[tuple[str, str], Labeled] = {}
    for x in scenarios:
        cmd = _norm_cmd(get(x.doc, "process.command_line"))
        if not cmd:
            continue
        key = (str(x.label.get("platform")), cmd)
        seen[key].add(x.label.get("technique"))
        first.setdefault(key, x)
    known = {_norm_cmd(get(x.doc, "process.command_line")) for x in attack}
    out = []
    for (platform, cmd), techs in seen.items():
        if len(techs) >= min_techniques and cmd not in known and not LAB_TRACE.search(cmd):
            out.append(Labeled(first[(platform, cmd)].doc, {"dataset": "scenario-background", "class": "normal",
                                                             "platform": platform, "seen_in_techniques": len(techs)}))
    return out


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
    ratio = lambda a, b: pct(a / b if b else None)  # noqa: E731
    lines = [
        "# Báo cáo độ phủ rule trên dataset công khai", "",
        "Sinh bởi `python -m siem.ai.benchmark`. Chỉ tính rule dạng `match` ở mức từng event "
        "(rule ngưỡng/chuỗi cần nhiều event liên tiếp nên không đánh giá trên request độc lập).", "",
        "| Lĩnh vực | Mẫu tấn công | Phát hiện | Nhóm có ít nhất 1 mẫu bị bắt | Mẫu bình thường | Báo nhầm |",
        "|---|---|---|---|---|---|",
    ]
    names = {"web": "Web (CSIC 2010)", "windows": "Windows", "linux": "Linux"}
    for key, d in rep.get("domains", {}).items():
        dom, src = d.get("domain", key), d.get("source")
        unit = "loại" if dom == "web" else "kỹ thuật"
        if src:          # dòng con theo nguồn dữ liệu: tập bình thường dùng chung với dòng tổng
            name, normal_cell, fp_cell = f"&nbsp;&nbsp;{names.get(dom, dom)}: {SOURCE_NAME.get(src, src)}", "", ""
        else:
            name = names.get(dom, dom) if dom == "web" else f"{names.get(dom, dom)} (tổng)"
            normal_cell = f"{d['normal']:,}"
            fp_cell = f"{d['false_positives']:,} ({ratio(d['false_positives'], d['normal'])})"
        lines.append(f"| {name} | {d['attack']:,} | {d['detected']:,} ({ratio(d['detected'], d['attack'])}) | "
                     f"{d['groups_detected']}/{d['groups']} {unit} | {normal_cell} | {fp_cell} |")
    lines += [
        "", f"Ngoài ra {rep['unobservable']:,} mẫu web nằm ngoài tầm nhìn (payload trong body POST/PUT, access log "
        "không ghi) — không tính. Mẫu endpoint gồm event tiến trình DỰNG LẠI từ lệnh của bài thử Atomic Red Team "
        "(`siem/ai/atomic.py`) và event tạo tiến trình GHI THẬT khi chạy tấn công (Splunk attack_data, "
        "`siem/ai/endpoint_logs.py`). Mẫu bình thường endpoint gồm lệnh quản trị tự soạn (`siem/ai/baseline.py`) và hoạt "
        "động nền ghi thật của máy Splunk Attack Range (chỉ Windows; giữ tiến trình lặp lại ở ≥ 2 kỹ thuật).", "",
    ]
    if rep.get("scenario"):
        lines += ["Đo theo bộ (log ghi thật chỉ biết cả bộ thuộc kỹ thuật nào: Splunk ngoài thư mục `atomic_red_team`, "
                  "OTRF). Một bộ tính là bị phát hiện khi rule bắn trên ít nhất một tiến trình của bộ:", "",
                  "| Bộ dữ liệu | Số bộ | Tiến trình | Bộ bị phát hiện | Kỹ thuật có ít nhất 1 bộ bị phát hiện |",
                  "|---|---|---|---|---|"]
        for key, d in rep["scenario"].items():
            dom, src = key.split("/")
            lines.append(f"| {names.get(dom, dom)}, {'Splunk' if src.startswith('splunk') else 'OTRF'} | {d['files']:,} | "
                         f"{d['events']:,} | {d['files_detected']:,} ({ratio(d['files_detected'], d['files'])}) | "
                         f"{d['techniques_detected']}/{d['techniques']} |")
        lines.append("")
    fp_ex = [(d.get("domain", dom), e) for dom, d in rep.get("domains", {}).items()
             if d.get("domain", dom) != "web" for e in d["fp_examples"]]
    if fp_ex:
        lines += ["Báo nhầm trên lệnh bình thường endpoint:", ""]
        lines += [f"- {dom}: `{e['event']}` — {', '.join(e['rules'])}" for dom, e in fp_ex]
        lines.append("")
    lines += [
        "## Web theo loại tấn công", "",
        "Nhóm do heuristic thô trong `siem/ai/attack_types.py` gán, chỉ để gom ứng viên cho AI. "
        "Loại *riêng ứng dụng* là bất thường của chính ứng dụng mẫu (tham số lạ, giá trị sai định dạng, "
        "đường dẫn không tồn tại): không viết được rule chữ ký dùng chung nên không giao cho AI.", "",
        "| Loại | Tổng | Phát hiện | Tỉ lệ | Giao cho AI viết rule |", "|---|---|---|---|---|",
    ]
    web = {k: v for k, v in rep["by_group"].items() if v.get("domain", "web") == "web"}
    for k, v in sorted(web.items(), key=lambda kv: (not PublicDatasets.transferable(kv[0]), -kv[1]["total"])):
        name = f"{TYPES[k].label} (`{k}`)" if k in TYPES else k
        ai = "có" if PublicDatasets.transferable(k) else "không (riêng ứng dụng)"
        lines.append(f"| {name} | {v.get('total', 0):,} | {v.get('detected', 0):,} | "
                     f"{pct(v.get('detected', 0) / v['total'] if v.get('total') else None)} | {ai} |")
    endpoint = {k: v for k, v in rep["by_group"].items() if v.get("domain") in ("windows", "linux") and v.get("tests")}
    if endpoint:
        lines += ["", "## Endpoint theo kỹ thuật ATT&CK", "",
                  "Nhóm = kỹ thuật gốc theo hệ điều hành. AI chỉ nhận nhóm có từ 4 bài thử chưa bị bắt (tách đôi "
                  "train / kiểm tra theo bài thử).", "",
                  "| Hệ điều hành | Kỹ thuật | Tên | Bài thử | Bài thử bị bắt | Tiến trình | Phát hiện | Tỉ lệ |",
                  "|---|---|---|---|---|---|---|---|"]
        for k, v in sorted(endpoint.items(), key=lambda kv: (kv[1]["domain"], -kv[1]["total"], kv[0])):
            lines.append(f"| {OS_NAME.get(v['domain'], v['domain'])} | {v['technique']} | {v['name']} | {v['tests']} | "
                         f"{v['tests_detected']} | {v['total']:,} | {v['detected']:,} | {ratio(v['detected'], v['total'])} |")
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
