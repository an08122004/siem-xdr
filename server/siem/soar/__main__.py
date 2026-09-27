"""Chạy SOAR service: python -m siem.soar"""
import logging
import time

from .. import bus, settings, store
from .cases import CasePlaybooks
from .engine import Notifier, Soar, load_playbooks

log = logging.getLogger("soar")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    es = store.connect()
    bus.wait_for_kafka()
    soar = Soar(
        es, load_playbooks(settings.CONFIG_DIR / "playbooks.yml"),
        auto_response=settings.SOAR_AUTO_RESPONSE, whitelist=settings.SOAR_WHITELIST,
        notifier=Notifier(settings.NOTIFY_WEBHOOK_URL, settings.TELEGRAM_BOT_TOKEN, settings.TELEGRAM_CHAT_ID),
        case_playbooks=CasePlaybooks(settings.CONFIG_DIR / "case_playbooks.yml"),
    )
    log.info("SOAR sẵn sàng (auto_response=%s)", settings.SOAR_AUTO_RESPONSE)
    last_hk = 0.0
    for alert in bus.consume("siem-soar", [settings.TOPIC_ALERTS]):
        if alert is not None:
            try:
                soar.handle(alert)
            except Exception:  # noqa: BLE001
                log.exception("xử lý alert lỗi")
        if time.time() - last_hk > 30:
            try:
                soar.housekeeping()
            except Exception:  # noqa: BLE001
                log.exception("housekeeping lỗi")
            last_hk = time.time()


if __name__ == "__main__":
    main()
