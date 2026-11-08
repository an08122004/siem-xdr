"""Dataset công khai (datasets/processed, tạo bởi tools/convert_datasets.py) dùng cho AI worker:

  - BỘ MẪU VÀNG (golden positives): event tấn công có nhãn — web (CSIC 2010 anomalous) và ENDPOINT
    (Atomic Red Team: lệnh tấn công Windows / Linux theo kỹ thuật ATT&CK; EVTX-ATTACK-SAMPLES nếu có).
    Mẫu Wazuh chưa bắt (sandbox Wazuh, wazuh_gate.py) là khoảng trống giao cho AI viết rule mới.
  - TẬP BÌNH THƯỜNG: request web (CSIC 2010 normal) + lệnh quản trị / hệ thống thông thường của Windows và Linux
    (baseline.py) -> đo báo nhầm của rule mới do AI đề xuất, theo đúng lĩnh vực của rule.
  - KHO SIGMA: tìm rule cộng đồng tương tự làm tài liệu tham khảo (RAG) khi đề xuất rule mới.

Lưu ý: event dataset được chạy OFFLINE (bộ chuẩn hóa, cây Python, sandbox Wazuh không mạng), KHÔNG bơm vào index thật
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
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
# nơi bài thử Atomic tự đặt tên file: thư mục tạm, thư mục Public, mã nguồn tự viết của bài thử (atomics/T…/src/).
# KHÔNG gồm ExternalPayloads / atomics/T…/bin: đó là công cụ tấn công thật tải về (SOAPHound, firepwd...) — tên của
# chúng là chữ ký hợp lệ; chính tên thư mục ExternalPayloads / AtomicRedTeam đã do ARTIFACT_RE chặn.
LAB_DIR = re.compile(r"[\\/](?:tmp|temp|shm)[\\/]|%te?mp%|\$env:te?mp|%public%|\$env:public|[\\/]users[\\/]public[\\/]"
                     r"|atomics[\\/]t\d{4}(?:\.\d{3})?[\\/]src[\\/]")
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
    _lab: dict[str, set[str]] = field(default_factory=dict)

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

    def lab_tokens(self, platform: str | None = None) -> set[str]:
        """Tên file do người viết bài thử Atomic tự đặt trong thư mục tạm / thư mục bài thử (giá trị mặc định của
        input_arguments: /tmp/evilBinary, .../T1548.001/src/hello.c -> evilbinary, hello.c, hello): rule dựa vào chúng
        chỉ bắt đúng bài thử. Dạng đoạn như validate._app_specific so (chữ thường, tách theo ký tự ngoài
        [a-z0-9_.-~]); lấy tên file và tên bỏ đuôi.
        KHÔNG lấy: tên trong thư mục khác (~/.netrc, id_rsa, C:\\Windows\\System32\\sethc.exe là thứ kẻ tấn công nhắm
        tới — chữ ký thật), dotfile, tên có trong lệnh bình thường / rule SigmaHQ / tên chương trình phổ biến (kể cả
        khi bỏ đuôi: %TEMP%\\svchost.exe không làm `svchost` thành dấu vết lab), đoạn ngắn / chỉ là số."""
        key = platform or "*"
        if key not in self._lab:
            from .validate import COMMON_PROGRAMS          # validate import golden -> import muộn
            seg = re.compile(r"[^a-z0-9_.\-~]+")
            values = {v for x in self.attack if platform is None or x.label.get("platform") == platform
                      for v in x.label.get("lab_values") or []}
            known = set(COMMON_PROGRAMS)
            for d in self.normal_for("endpoint", platform):
                known |= set(seg.split(f"{get(d, 'process.command_line') or ''} {get(d, 'process.executable') or ''}"
                                       .lower()))
            for r in self.sigma:
                known |= set(seg.split(str(r.get("detection") or "").lower().replace("*", " ")))
            known |= {k.rsplit(".", 1)[0] for k in known if "." in k.strip(".")}
            cand = set()
            for v in values:
                v = v.strip().strip("\"'").lower()
                if not LAB_DIR.search(v):
                    continue
                for s in seg.split(re.split(r"[\\/]", v)[-1]):
                    if s.startswith("."):
                        continue
                    cand |= {s, s.rsplit(".", 1)[0]} if "." in s.strip(".") else {s}
            self._lab[key] = {s for s in cand if len(s) >= 4 and re.search(r"[a-z]", s)
                              and not re.fullmatch(r"[0-9a-f.\-]+", s) and s not in known}
        return self._lab[key]

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
