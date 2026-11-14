"""Phát hiện bất thường bằng Isolation Forest, mỗi nguồn một model (web / auth).

Mỗi model gom event theo (IP nguồn, cửa sổ thời gian) thành một vector đặc trưng. Model chỉ học từ lưu lượng thật:
giai đoạn học kéo dài tới khi đủ `learn_hours` kể từ cửa sổ đầu tiên VÀ đủ `min_windows` cửa sổ; sau đó fit Isolation
Forest trên 80% cửa sổ cũ, ngưỡng = phân vị `target_fp` của điểm trên 20% cửa sổ mới nhất (tập giữ lại, ≥ 50), tức tỉ
lệ báo nhầm có chủ đích. Cửa sổ bị gắn cờ hay của IP đang im lặng vẫn được lưu (có cờ) để hiệu chỉnh ngưỡng nhưng không
dùng để fit; cửa sổ bị `exclude` (IP có alert thật) thì không lưu.
Trạng thái lưu dạng JSON (vector, không lưu model) và fit lại khi nạp: pickle scikit-learn vỡ giữa các phiên bản.
"""
from __future__ import annotations

import json
import logging
import math
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from ..pipeline.normalize import Doc, get

log = logging.getLogger(__name__)

FEATURES_WEB = ("n_requests", "n_paths", "ratio_4xx", "n_401", "n_404", "kb_out", "n_agents")
FEATURES_AUTH = ("n_attempts", "n_fail", "fail_ratio", "n_users", "n_success")

CAP = 1000            # phần tử tối đa mỗi tập trong một cửa sổ
MAX_IDS = 20          # event.id giữ lại mỗi cửa sổ
MAX_TRAIN = 20_000    # cửa sổ lưu tối đa mỗi model (kể cả bị gắn cờ)
MAX_NUM = 1e15        # giá trị số từ event lớn hơn thế là rác (byte của một response): coi như 0
HOLDOUT_MIN = 50
IDLE_SECONDS = 60     # không có event lâu chừng này (theo đồng hồ) thì đóng cửa sổ theo đồng hồ thay vì thời gian event
VERSION = 2


@dataclass(frozen=True)
class ModelSpec:
    name: str
    rule_id: str
    title: str
    window: int
    min_events: int
    features: tuple[str, ...]
    tactic: str
    technique: str


SPECS: dict[str, ModelSpec] = {
    "web": ModelSpec("web", "ML-WEB", "Hành vi web bất thường của IP nguồn", 300, 5, FEATURES_WEB,
                     "Reconnaissance", "T1595"),
    "auth": ModelSpec("auth", "ML-AUTH", "Hành vi đăng nhập bất thường của IP nguồn", 600, 1, FEATURES_AUTH,
                      "Credential Access", "T1110"),
}


def accepts(spec: ModelSpec, doc: Doc) -> bool:
    if not get(doc, "source.ip") or get(doc, "source.ip_scope") == "loopback":
        return False
    if spec.name == "web":
        return get(doc, "event.category") == "web" and get(doc, "http.response.status_code") is not None
    return get(doc, "event.category") == "authentication"


def _num(v) -> float:
    """Số hữu hạn trong [0, MAX_NUM), còn lại 0: NaN / vô cực / âm từ log không được làm hỏng vector."""
    try:
        x = float(v or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return x if 0 <= x < MAX_NUM else 0.0


def _finite(v) -> float:
    x = float(v)
    if not math.isfinite(x):
        raise ValueError(f"giá trị không hữu hạn {x}")
    return x


def _put(s: set, v) -> None:
    if v is not None and len(s) < CAP:
        s.add(v)


class Window:
    """Bộ cộng dồn event của một (model, IP, cửa sổ)."""

    def __init__(self, spec: ModelSpec) -> None:
        self.spec = spec
        self.n = 0
        self.n4xx = self.n401 = self.n404 = self.fail = self.success = 0
        self.bytes = 0.0
        self.paths: set = set()
        self.agents: set = set()
        self.users: set = set()
        self.last_event: Doc = {}
        self.event_ids: list[str] = []

    def add(self, doc: Doc) -> None:
        self.n += 1
        self.last_event = doc
        if len(self.event_ids) < MAX_IDS and (eid := get(doc, "event.id")) is not None:
            self.event_ids.append(eid)
        if self.spec.name == "web":
            status = _num(get(doc, "http.response.status_code"))
            self.n4xx += 400 <= status < 500
            self.n401 += status == 401
            self.n404 += status == 404
            self.bytes += _num(get(doc, "http.response.bytes"))
            _put(self.paths, get(doc, "url.path"))
            _put(self.agents, get(doc, "user_agent.original"))
        else:
            outcome = get(doc, "event.outcome")
            self.fail += outcome == "failure"
            self.success += outcome == "success"
            _put(self.users, get(doc, "user.name"))

    def vector(self) -> list[float]:
        n = max(self.n, 1)
        if self.spec.name == "web":
            v = [self.n, len(self.paths), self.n4xx / n, self.n401, self.n404, self.bytes / 1024, len(self.agents)]
        else:
            v = [self.n, self.fail, self.fail / n, len(self.users), self.success]
        return [float(x) for x in v]


@dataclass
class Anomaly:
    model: str
    entity: str
    score: float
    threshold: float
    features: dict[str, float]
    top: list[tuple[str, float, float]]
    event: Doc
    event_ids: list[str]
    window_start: float


def _matrix(spec: ModelSpec, vectors: list[list[float]]) -> np.ndarray:
    # đặc trưng đếm qua log1p để giá trị cực lớn không lấn át; tỉ lệ để nguyên
    x = np.array(vectors, dtype=float)
    counts = [i for i, f in enumerate(spec.features) if "ratio" not in f]
    x[:, counts] = np.log1p(x[:, counts])
    return x


def windows_from_events(docs: Iterable[tuple[Doc, float]], spec: ModelSpec) -> list[tuple[str, float, list[float], Window]]:
    """Gom (event, thời điểm) thành cửa sổ như `AnomalyDetector.add`; chỉ trả cửa sổ đủ `min_events` (giống bản
    online: cửa sổ nhỏ hơn không được chấm điểm cũng không được học). Sắp theo thời gian cửa sổ."""
    wins: dict[tuple[int, str], Window] = {}
    for doc, ts in docs:
        if accepts(spec, doc):
            wins.setdefault((int(ts // spec.window), get(doc, "source.ip")), Window(spec)).add(doc)
    return [(ip, float(idx * spec.window), w.vector(), w)
            for (idx, ip), w in sorted(wins.items(), key=lambda kv: kv[0][0]) if w.n >= spec.min_events]


@dataclass
class _Model:
    spec: ModelSpec
    open: dict[int, dict[str, Window]] = field(default_factory=dict)
    excluded: set[tuple[str, int]] = field(default_factory=set)
    silenced: dict[str, float] = field(default_factory=dict)        # IP -> hết im lặng (thời gian cửa sổ)
    train: list[list[float]] = field(default_factory=list)          # vector cửa sổ đã lưu, cũ -> mới
    flags: list[bool] = field(default_factory=list)                 # song song với train: True = không dùng để fit
    first_seen: float | None = None
    last_fit: float | None = None
    forest: IsolationForest | None = None
    threshold: float | None = None
    median: list[float] = field(default_factory=list)
    scored: int = 0
    flagged: int = 0
    dropped_late: int = 0
    dropped_entities: int = 0
    # watermark theo thời gian EVENT, riêng mỗi model (nguồn auth có thể trễ hơn nguồn web): cửa sổ hết trước mốc này
    # (+ grace) đã đóng và không bao giờ mở lại
    watermark: float | None = None
    max_ts: float | None = None             # thời gian event lớn nhất model đã nhận (kẹp theo đồng hồ ở flush)
    last_event_now: float | None = None     # `now` của lần flush gần nhất model có event mới
    arrived: bool = False


class AnomalyDetector:
    def __init__(self, state_path: Path | None = None, learn_hours: float = 48, min_windows: int = 200,
                 target_fp: float = 0.005, cooldown: float = 1800, retrain_hours: float = 24, grace: int = 30,
                 specs: dict[str, ModelSpec] = SPECS, max_entities: int = 50_000) -> None:
        self.state_path = state_path
        self.learn_hours, self.min_windows, self.target_fp = learn_hours, min_windows, target_fp
        self.cooldown, self.retrain_hours, self.grace = cooldown, retrain_hours, grace
        self.max_entities = max_entities
        self.models = {name: _Model(spec) for name, spec in specs.items()}
        self._load()

    # ---------------- online ----------------
    def add(self, doc: Doc, ts: float) -> None:
        for m in self.models.values():
            if not accepts(m.spec, doc):
                continue
            m.max_ts = ts if m.max_ts is None else max(m.max_ts, ts)
            m.arrived = True
            idx = int(ts // m.spec.window)
            if m.watermark is not None and (idx + 1) * m.spec.window + self.grace <= m.watermark:
                m.dropped_late += 1          # cửa sổ đã đóng (kể cả trước khi khởi động lại): không mở lại thành nửa cửa sổ
                continue
            per_ip = m.open.setdefault(idx, {})
            ip = get(doc, "source.ip")
            if ip not in per_ip and len(per_ip) >= self.max_entities:
                m.dropped_entities += 1      # đếm theo event bị bỏ: nhớ tập IP bị bỏ lại tốn đúng bộ nhớ đang chặn
                continue
            per_ip.setdefault(ip, Window(m.spec)).add(doc)

    def exclude(self, entity: str, ts: float) -> None:
        """IP có alert thật ở thời điểm ts: cửa sổ chứa ts của IP đó không vào tập học (D5)."""
        for m in self.models.values():
            m.excluded.add((entity, int(ts // m.spec.window)))

    def flush(self, now: float) -> list[Anomaly]:
        out: list[Anomaly] = []
        for m in self.models.values():
            _advance(m, now)
            self._maybe_fit(m, now)
            if m.watermark is None:
                continue
            w = m.spec.window
            for idx in sorted(i for i in m.open if (i + 1) * w + self.grace <= m.watermark):
                out += self._close(m, idx, m.open.pop(idx))
            # nhờ watermark, cửa sổ nào đóng sau lần này đều bắt đầu sau `horizon`: mục loại trừ / im lặng cũ hơn vô dụng
            horizon = m.watermark - self.grace - w
            m.excluded = {(ip, i) for ip, i in m.excluded if i * w > horizon}
            m.silenced = {ip: t for ip, t in m.silenced.items() if t > horizon}
        return out

    def _close(self, m: _Model, idx: int, per_ip: dict[str, Window]) -> list[Anomaly]:
        start = float(idx * m.spec.window)
        items = [(ip, win, win.vector()) for ip, win in per_ip.items() if win.n >= m.spec.min_events]
        if not items:
            return []
        scores = m.forest.decision_function(_matrix(m.spec, [v for _, _, v in items])) if m.forest is not None else None
        out = []
        for k, (ip, win, vec) in enumerate(items):
            silenced = start < m.silenced.get(ip, float("-inf"))
            flagged = scores is not None and bool(scores[k] < m.threshold)
            if scores is not None:
                m.scored += 1
                m.flagged += flagged
            if flagged and not silenced:
                m.silenced[ip] = start + self.cooldown
                out.append(Anomaly(m.spec.name, ip, float(scores[k]), float(m.threshold),
                                   dict(zip(m.spec.features, vec)), _top(m, vec), win.last_event, win.event_ids, start))
            if (ip, idx) not in m.excluded:
                m.train.append(vec)
                m.flags.append(flagged or silenced)
                if m.first_seen is None:
                    m.first_seen = start
        del m.train[:-MAX_TRAIN]
        del m.flags[:-MAX_TRAIN]
        return out

    # ---------------- học ----------------
    def _maybe_fit(self, m: _Model, now: float) -> None:
        if m.forest is None:
            due = (m.first_seen is not None and now - m.first_seen >= self.learn_hours * 3600
                   and len(m.train) >= self.min_windows)
        else:
            due = m.last_fit is None or now - m.last_fit >= self.retrain_hours * 3600
        if due and len(m.train) >= 2 * HOLDOUT_MIN:
            self._fit(m, now)

    def _fit(self, m: _Model, now: float) -> None:
        x = _matrix(m.spec, m.train)
        ok = ~np.array(m.flags, dtype=bool)
        hold = max(HOLDOUT_MIN, len(x) // 5)
        base = x[:-hold][ok[:-hold]]
        if len(base) < HOLDOUT_MIN:
            return
        forest = IsolationForest(n_estimators=200, random_state=0).fit(base)
        # ngưỡng trên MỌI cửa sổ mới nhất, kể cả bị gắn cờ: bỏ chúng thì tập hiệu chỉnh thiếu đúng phần đuôi model cũ đã
        # cắt và mỗi lần fit lại ngưỡng nhích lên (tỉ lệ gắn cờ trôi dần ~ phần đã gắn cờ + target_fp)
        threshold = float(np.quantile(forest.decision_function(x[-hold:]), self.target_fp))
        if m.forest is None:
            m.scored = m.flagged = 0
            log.info("ML %s: chuyển sang active (%d cửa sổ, ngưỡng %.3f)", m.spec.name, len(x), threshold)
        m.forest, m.threshold, m.last_fit = forest, threshold, now
        m.median = np.median(np.array(m.train)[ok], axis=0).tolist()

    def seed(self, name: str, vectors: list[list[float]], first_seen: float) -> None:
        """Khởi tạo offline (tools/ml_eval.py): thay tập học; model được fit ở lần flush kế tiếp nếu đủ điều kiện."""
        m = self.models[name]
        m.train = [[float(x) for x in v] for v in vectors][-MAX_TRAIN:]
        m.flags = [False] * len(m.train)
        m.first_seen, m.forest, m.threshold, m.last_fit = first_seen, None, None, None

    # ---------------- trạng thái ----------------
    def status(self) -> dict[str, dict]:
        """`windows` = số cửa sổ đang lưu, kể cả cửa sổ bị gắn cờ (chỉ dùng hiệu chỉnh ngưỡng, không fit)."""
        return {name: {"phase": "active" if m.forest is not None else "learning", "windows": len(m.train),
                       "threshold": m.threshold, "first_seen": m.first_seen, "dropped_late": m.dropped_late,
                       "dropped_entities": m.dropped_entities} for name, m in self.models.items()}

    def flagged_ratio(self, name: str) -> float:
        """Số cửa sổ bị gắn cờ / số cửa sổ đã chấm điểm, kể từ khi model chuyển sang active."""
        m = self.models[name]
        return m.flagged / m.scored if m.scored else 0.0

    def save(self) -> None:
        if not self.state_path:
            return
        data = {"version": VERSION,
                "models": {name: {"train": m.train, "flagged": m.flags, "first_seen": m.first_seen,
                                  "last_fit": m.last_fit, "watermark": m.watermark} for name, m in self.models.items()}}
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self.state_path)
        except OSError as e:
            log.warning("ML: không lưu được trạng thái %s: %s", self.state_path, e)

    def _load(self) -> None:
        """Nạp tập học đã lưu; model fit lại ở lần flush đầu (nếu đủ điều kiện). Hỏng / khác version -> học từ đầu."""
        if not self.state_path or not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if data.get("version") != VERSION:
                raise ValueError(f"version {data.get('version')!r}")
            # file cũ có một watermark chung ("last_flush" của cc2da4a, "watermark" của 74e15f1): áp cho mọi model
            shared, loaded = data.get("watermark", data.get("last_flush")), {}
            for name, m in self.models.items():
                s = data["models"].get(name) or {}
                train = [[_finite(x) for x in v] for v in s.get("train", [])]
                if any(len(v) != len(m.spec.features) for v in train):
                    raise ValueError(f"vector {name} sai số chiều")
                flags = s.get("flagged", [False] * len(train))     # file cũ chưa có cờ: coi như không bị gắn cờ
                if len(flags) != len(train) or not all(isinstance(f, bool) for f in flags):
                    raise ValueError(f"cờ {name} không khớp vector")
                loaded[name] = (train[-MAX_TRAIN:], flags[-MAX_TRAIN:], _opt(s.get("first_seen")), _opt(s.get("last_fit")),
                                _opt(s.get("watermark", shared)))
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            log.warning("ML: file trạng thái %s hỏng hoặc khác version (%s), học lại từ đầu", self.state_path, e)
            return
        for name, (train, flags, first, last_fit, watermark) in loaded.items():
            m = self.models[name]
            m.train, m.flags, m.first_seen, m.last_fit, m.watermark = train, flags, first, last_fit, watermark
        log.info("ML: nạp trạng thái %s (%s)", self.state_path,
                 ", ".join(f"{n} {len(m.train)} cửa sổ" for n, m in self.models.items()))


def _advance(m: _Model, now: float) -> None:
    """Watermark của model = thời gian event lớn nhất model nhận (không vượt đồng hồ): backlog cũ (khởi động lại, agent
    dồn log) vẫn rơi đúng cửa sổ và đóng đủ. Model im IDLE_SECONDS thì theo đồng hồ để cửa sổ cuối không treo mãi."""
    if m.arrived or m.last_event_now is None:     # lần flush đầu (vừa khởi động) cũng tính là mốc
        m.last_event_now, m.arrived = now, False
    if now - m.last_event_now >= IDLE_SECONDS:
        # shortcut: Kafka nghẽn > IDLE_SECONDS giữa lúc phát lại backlog thì quy tắc này đóng nửa cửa sổ và phần backlog
        # còn lại bị bỏ như event muộn (có đếm dropped_late), nâng cấp khi analyzer biết trạng thái lag của consumer
        wm = now
    elif m.max_ts is not None:
        # event ghi giờ tương lai chỉ kéo được tới đồng hồ, một lần, rồi watermark lại theo thời gian event
        m.max_ts = wm = min(m.max_ts, now)
    else:
        return
    if m.watermark is None or wm > m.watermark:
        m.watermark = wm


def _opt(v) -> float | None:
    return None if v is None else _finite(v)


def _top(m: _Model, vec: list[float]) -> list[tuple[str, float, float]]:
    """D8: tối đa 3 đặc trưng có (x + 1) / (trung vị + 1) ≥ 2, xếp giảm dần."""
    ratios = [((x + 1) / (med + 1), f, x, med) for f, x, med in zip(m.spec.features, vec, m.median)]
    return [(f, x, med) for r, f, x, med in sorted(ratios, reverse=True) if r >= 2][:3]


def severity(a: Anomaly) -> str:
    """D9: theo khoảng cách dưới ngưỡng."""
    m = a.threshold - a.score
    return "high" if m > 0.15 else "medium" if m > 0.05 else "low"


def _fmt(v: float) -> str:
    return f"{v:.0f}" if float(v).is_integer() else f"{v:.2f}"


def explain(a: Anomaly) -> str:
    """D8: `n_paths=340 (thường 8), ...`; chuỗi rỗng khi không đặc trưng nào lệch ≥ 2 lần."""
    return ", ".join(f"{f}={_fmt(x)} (thường {_fmt(med)})" for f, x, med in a.top)
