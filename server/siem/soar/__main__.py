"""Chạy SOAR service: python -m siem.soar"""
import logging
import time

from .. import bus, settings, store
from ..pipeline.enrich import AssetDB
from . import risk
from .cases import CasePlaybooks
from .engine import Notifier, Soar, load_playbooks
from .health import HealthMonitor, kafka_lag_reader
from .wazuh import Responder, WazuhAPI

log = logging.getLogger("soar")


class Every:
    """Chạy fn mỗi `seconds` giây; lỗi chỉ ghi log, không làm dừng SOAR."""

    def __init__(self, seconds: float, name: str, fn):
        self.seconds, self.name, self.fn, self.last = seconds, name, fn, 0.0

    def __call__(self) -> None:
        if time.time() - self.last < self.seconds:
            return
        self.last = time.time()
        try:
            self.fn()
        except Exception as e:  # noqa: BLE001
            log.warning("%s lỗi: %s", self.name, e)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    es = store.connect()
    bus.wait_for_kafka()
    soar = Soar(
        es, load_playbooks(settings.CONFIG_DIR / "playbooks.yml"),
        auto_response=settings.SOAR_AUTO_RESPONSE, whitelist=settings.SOAR_WHITELIST,
        notifier=Notifier(settings.NOTIFY_WEBHOOK_URL, settings.TELEGRAM_BOT_TOKEN, settings.TELEGRAM_CHAT_ID,
                          cooldown=settings.NOTIFY_COOLDOWN_SECONDS),
        case_playbooks=CasePlaybooks(settings.CONFIG_DIR / "case_playbooks.yml"),
        max_auto_kills=settings.SOAR_MAX_AUTO_KILLS,
        risk=risk.from_settings() if settings.RBA_ENABLED else None,
    )
    if soar.risk is not None:
        try:
            soar.risk.load(es)
        except Exception as e:  # noqa: BLE001 - chưa có alert nào: bắt đầu với cửa sổ rỗng
            log.warning("RBA: không dựng lại được cửa sổ điểm rủi ro: %s", e)
    tasks = [Every(30, "housekeeping", soar.housekeeping)]
    if settings.HEALTH_ENABLED:
        health = HealthMonitor(es, soar.emit, assets=AssetDB(settings.CONFIG_DIR / "assets.yml"),
                               kafka_lag=kafka_lag_reader({"siem-analyzer": [settings.TOPIC_RAW],
                                                           "siem-soar": [settings.TOPIC_ALERTS]}))
        tasks.append(Every(60, "giám sát sức khỏe nguồn log / nền tảng", health.run))
    if settings.WAZUH_API_PASSWORD:
        responder = Responder(es, WazuhAPI(settings.WAZUH_API_URL, settings.WAZUH_API_USER,
                                           settings.WAZUH_API_PASSWORD, settings.WAZUH_API_CA))
        tasks += [Every(30, "đồng bộ agent từ Wazuh", responder.sync_agents),
                  Every(2, "gửi lệnh qua Wazuh", responder.dispatch),
                  Every(5, "nhận kết quả lệnh", responder.collect_results)]
    else:
        log.warning("chưa cấu hình WAZUH_API_PASSWORD: lệnh phản ứng chỉ được tạo, KHÔNG gửi xuống agent")
    log.info("SOAR sẵn sàng (auto_response=%s, Wazuh API=%s)", settings.SOAR_AUTO_RESPONSE, settings.WAZUH_API_URL)
    stream = bus.consume("siem-soar", [settings.TOPIC_ALERTS])
    for alert in stream:
        if alert is not None:
            try:
                soar.handle(alert)
            except Exception:  # noqa: BLE001
                log.exception("xử lý alert lỗi")
            stream.done()          # xác nhận sau khi xử lý xong (dừng giữa chừng thì lần sau xử lý lại alert này)
        for t in tasks:
            t()


if __name__ == "__main__":
    main()
