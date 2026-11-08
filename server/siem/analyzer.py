"""Analyzer — trái tim của SIEM:

    Kafka [siem.raw] -> normalize -> enrich -> (1) Elasticsearch siem-events-*
                                             -> (2) ML anomaly   ┐-> alert -> ES siem-alerts
    (cảnh báo ruleset Wazuh, event_type wazuh_alert) -> (3) cầu nối ┘       -> Kafka [siem.alerts] -> SOAR
Phát hiện bằng rule chạy hoàn toàn trong wazuh-analysisd (R65); engine YAML đã xóa ở Task 25.
Chạy: python -m siem.analyzer
"""
from __future__ import annotations

import contextlib
import logging
import time

from . import bus, settings, store
from .detection import alerts as alert_builder
from .detection import ml
from .detection import wazuh as wazuh_bridge
from .pipeline.enrich import default_enricher
from .pipeline.normalize import get, normalize

log = logging.getLogger("analyzer")

FLUSH_EVERY = 1.0
FLUSH_SIZE = 500


class Analyzer:
    def __init__(self) -> None:
        self.enricher = default_enricher()
        self.detector = ml.AnomalyDetector(
            window=settings.ML_WINDOW_SECONDS, min_samples=settings.ML_MIN_SAMPLES,
            contamination=settings.ML_CONTAMINATION, model_dir=settings.DATA_DIR / "models",
            bootstrap=settings.ML_BOOTSTRAP_SYNTHETIC,
        ) if settings.ML_ENABLED else None
        self.es = store.connect()
        bus.wait_for_kafka()
        self.producer = bus.producer()
        self.buffer: list[dict] = []
        self.last_flush = time.time()
        self.stats = {"events": 0, "alerts": 0}
        self.suppressor = wazuh_bridge.Suppressor()
        self.stream: bus.Stream | None = None

    def handle(self, raw: dict) -> None:
        doc = self.enricher.enrich(normalize(raw))
        if raw.get("event_type") == "wazuh_alert":
            # cảnh báo từ alerts.json của Wazuh: event gốc đã đến qua archives.json (được lưu ở đó), ở đây chuyển cảnh
            # báo thành alert theo bộ lọc của cầu nối (detection/wazuh.py)
            if (alert := wazuh_bridge.to_alert(doc)):
                if get(alert, "alert.shadow") or not self.suppressor.seen(wazuh_bridge.suppress_key(doc), time.monotonic()):
                    self.emit(alert)
            return
        self.buffer.append({"_index": store.events_index(doc.get("@timestamp")), "_id": doc["event"]["id"], "_source": doc})
        self.stats["events"] += 1
        if self.detector:
            self.detector.add(doc, alert_builder.event_time(doc))

    def emit(self, alert: dict) -> None:
        self.stats["alerts"] += 1
        log.warning("ALERT %s", alert["message"])
        # alert ít nên ghi ngay (không qua buffer) để SOAR cập nhật được ngay khi nhận
        try:
            self.es.index(index=settings.IDX_ALERTS, id=alert["alert"]["id"], document=alert)
        except Exception as e:  # noqa: BLE001
            log.error("không ghi được alert vào ES: %s", e)
        bus.send(self.producer, settings.TOPIC_ALERTS, alert, key=alert["alert"]["id"])

    def tick(self) -> None:
        now = time.time()
        if self.detector:
            for a in self.detector.flush(now):
                self.emit(alert_builder.from_anomaly(a, ml.severity_for(a.score), ml.describe(a), ml.feature_dict(a)))
        if self.buffer and (len(self.buffer) >= FLUSH_SIZE or now - self.last_flush >= FLUSH_EVERY):
            try:
                store.bulk_index(self.es, self.buffer)
            except Exception as e:  # noqa: BLE001
                log.error("ghi Elasticsearch lỗi (sẽ thử lại): %s", e)
                time.sleep(2)
                return
            self.buffer.clear()
            self.last_flush = now
        if not self.buffer:
            # mọi message đã đọc đều đã ghi ES; alert đã sinh phải tới được Kafka thì mới xác nhận offset
            if self.producer.flush(5) == 0 and self.stream is not None:
                self.stream.done()

    def run(self) -> None:
        log.info("analyzer bắt đầu tiêu thụ topic %s", settings.TOPIC_RAW)
        last_report = time.time()
        self.stream = bus.consume("siem-analyzer", [settings.TOPIC_RAW], poll_timeout=0.5)
        for msg in self.stream:
            if msg is not None:
                try:
                    self.handle(msg)
                except Exception:  # noqa: BLE001
                    log.exception("xử lý event lỗi")
            if msg is None or len(self.buffer) >= FLUSH_SIZE or time.time() - self.last_flush >= FLUSH_EVERY:
                self.tick()
            if time.time() - last_report > 60:
                log.info("thống kê: %s", self.stats)
                last_report = time.time()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    Analyzer().run()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):   # docker stop gửi SIGINT (stop_signal): thoát êm, không in traceback
        main()
