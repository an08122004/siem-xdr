"""Phát hiện bất thường — phân tích DỰA TRÊN MACHINE LEARNING.

Ý tưởng: gom event theo (cửa sổ thời gian W giây, IP nguồn) thành 1 vector đặc
trưng hành vi, rồi dùng Isolation Forest (học không giám sát) để tìm các vector
"lạ" so với phần đông. Không cần dữ liệu tấn công có nhãn.

Đặc trưng cho mỗi (IP, cửa sổ):
  0 n_events            tổng số event
  1 n_dst_ports         số port đích khác nhau        (port scan)
  2 n_urls              số URL path khác nhau          (dò quét web, dirbusting)
  3 err_ratio           tỉ lệ HTTP >= 400 / thất bại  (brute-force, fuzzing)
  4 n_auth_fail         số lần đăng nhập thất bại
  5 n_users             số username khác nhau          (password spraying)
  6 n_denied            số kết nối bị firewall chặn
  7 bytes_kb            tổng dung lượng phản hồi HTTP (exfiltration)

Mô hình được huấn luyện liên tục trên dữ liệu thật (và có thể khởi tạo từ baseline
tổng hợp cho lab), lưu bằng joblib để khởi động lại không phải học từ đầu.
"""
from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ..pipeline.normalize import Doc, get

log = logging.getLogger(__name__)

FEATURES = ["n_events", "n_dst_ports", "n_urls", "err_ratio", "n_auth_fail", "n_users", "n_denied", "bytes_kb"]
MAX_TRAIN = 5000


@dataclass
class _Bucket:
    n: int = 0
    ports: set = field(default_factory=set)
    urls: set = field(default_factory=set)
    errors: int = 0
    auth_fail: int = 0
    users: set = field(default_factory=set)
    denied: int = 0
    bytes: int = 0
    last_event: Doc | None = None
    event_ids: list = field(default_factory=list)

    def add(self, doc: Doc) -> None:
        self.n += 1
        if (p := get(doc, "destination.port")) is not None:
            self.ports.add(p)
        if (u := get(doc, "url.path")) is not None and len(self.urls) < 1000:
            self.urls.add(u)
        status = get(doc, "http.response.status_code")
        if (status and status >= 400) or get(doc, "event.outcome") == "failure":
            self.errors += 1
        if get(doc, "event.category") == "authentication" and get(doc, "event.outcome") == "failure":
            self.auth_fail += 1
        if (u := get(doc, "user.name")) is not None and len(self.users) < 1000:
            self.users.add(u)
        if get(doc, "event.action") == "deny":
            self.denied += 1
        self.bytes += get(doc, "http.response.bytes") or 0
        self.last_event = doc
        if len(self.event_ids) < 20:
            self.event_ids.append(get(doc, "event.id"))

    def vector(self) -> list[float]:
        return [self.n, len(self.ports), len(self.urls), self.errors / max(self.n, 1),
                self.auth_fail, len(self.users), self.denied, self.bytes / 1024]


@dataclass
class Anomaly:
    ip: str
    score: float
    features: dict[str, float]
    event: Doc
    event_ids: list


def _transform(x: np.ndarray) -> np.ndarray:
    # log1p cho các đặc trưng dạng đếm để giảm ảnh hưởng của giá trị cực lớn
    x = x.copy()
    idx = [0, 1, 2, 4, 5, 6, 7]
    x[:, idx] = np.log1p(x[:, idx])
    return x


def synthetic_baseline(n: int = 600, seed: int = 42) -> np.ndarray:
    """Baseline 'bình thường' tổng hợp cho lab: người dùng duyệt web vài chục
    request/phút, thỉnh thoảng lỗi 404, rất ít đăng nhập sai."""
    rng = np.random.default_rng(seed)
    n_events = rng.poisson(12, n) + 1
    return np.column_stack([
        n_events,
        rng.choice([0, 1, 1, 2], n),
        np.minimum(n_events, rng.poisson(6, n) + 1),
        np.clip(rng.beta(1, 12, n), 0, 1),
        rng.choice([0, 0, 0, 0, 1], n),
        rng.choice([0, 1, 1], n),
        rng.choice([0, 0, 0, 1], n),
        rng.gamma(2, 60, n),
    ]).astype(float)


class AnomalyDetector:
    def __init__(self, window: int = 60, min_samples: int = 50, contamination: float = 0.02,
                 model_dir: Path | None = None, bootstrap: bool = True, score_threshold: float = -0.05):
        self.window = window
        self.min_samples = min_samples
        self.contamination = contamination
        self.score_threshold = score_threshold
        self.model_path = (model_dir / "isoforest.joblib") if model_dir else None
        self.buckets: dict[int, dict[str, _Bucket]] = defaultdict(lambda: defaultdict(_Bucket))
        self.train: list[list[float]] = []
        self.model: IsolationForest | None = None
        self.windows_since_fit = 0
        self._load(bootstrap)

    # ---------------- persistence ----------------
    def _load(self, bootstrap: bool) -> None:
        if self.model_path and self.model_path.exists():
            try:
                state = joblib.load(self.model_path)
                self.model, self.train = state["model"], state["train"]
                log.info("ML: nạp model từ %s (%d mẫu)", self.model_path, len(self.train))
                return
            except Exception as e:  # noqa: BLE001
                log.warning("ML: không nạp được model: %s", e)
        if bootstrap:
            self.train = synthetic_baseline().tolist()
            self._fit()
            log.info("ML: khởi tạo model từ baseline tổng hợp (%d mẫu)", len(self.train))

    def _save(self) -> None:
        if not self.model_path:
            return
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": self.model, "train": self.train}, self.model_path)
        except OSError as e:
            log.warning("ML: không lưu được model: %s", e)

    def _fit(self) -> None:
        x = _transform(np.array(self.train[-MAX_TRAIN:], dtype=float))
        self.model = IsolationForest(n_estimators=150, contamination=self.contamination, random_state=0)
        self.model.fit(x)
        self.windows_since_fit = 0

    # ---------------- online ----------------
    def add(self, doc: Doc, ts: float) -> None:
        ip = get(doc, "source.ip")
        if not ip or get(doc, "source.ip_scope") == "loopback":
            return
        self.buckets[int(ts // self.window)][ip].add(doc)

    def flush(self, now: float, grace: int = 10) -> list[Anomaly]:
        """Đóng các cửa sổ đã kết thúc (quá grace giây), chấm điểm, cập nhật tập train."""
        current = int((now - grace) // self.window)
        anomalies: list[Anomaly] = []
        for w in sorted(k for k in self.buckets if k < current):
            per_ip = self.buckets.pop(w)
            if not per_ip:
                continue
            ips = list(per_ip)
            vecs = [per_ip[ip].vector() for ip in ips]
            if self.model is not None:
                scores = self.model.decision_function(_transform(np.array(vecs, dtype=float)))
                for ip, vec, s in zip(ips, vecs, scores):
                    if s < self.score_threshold:
                        b = per_ip[ip]
                        anomalies.append(Anomaly(ip, float(s), dict(zip(FEATURES, vec)), b.last_event or {}, b.event_ids))
            # chỉ học từ các mẫu KHÔNG bị coi là bất thường, tránh "đầu độc" baseline
            flagged = {a.ip for a in anomalies}
            self.train.extend(v for ip, v in zip(ips, vecs) if ip not in flagged)
            self.train = self.train[-MAX_TRAIN:]
            self.windows_since_fit += 1
        if len(self.train) >= self.min_samples and (self.model is None or self.windows_since_fit >= 10):
            self._fit()
            self._save()
            log.info("ML: huấn luyện lại với %d mẫu", len(self.train))
        return anomalies


def severity_for(score: float) -> str:
    if score < -0.2:
        return "high"
    if score < -0.1:
        return "medium"
    return "low"


def describe(a: Anomaly) -> str:
    top = sorted(((k, v) for k, v in a.features.items()), key=lambda kv: -math.log1p(abs(kv[1])))[:4]
    return ", ".join(f"{k}={v:.2f}" if isinstance(v, float) and not v.is_integer() else f"{k}={int(v)}" for k, v in top)


def feature_dict(a: Anomaly) -> dict[str, Any]:
    return {k: round(v, 3) for k, v in a.features.items()}
