"""Tiện ích Kafka (message bus trung tâm của pipeline).

    agent/syslog --> [siem.raw] --> analyzer --> [siem.alerts] --> soar
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterator

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from . import settings

log = logging.getLogger(__name__)


def wait_for_kafka(timeout: int = 180) -> None:
    admin = AdminClient({"bootstrap.servers": settings.KAFKA_BOOTSTRAP})
    deadline = time.time() + timeout
    while True:
        try:
            admin.list_topics(timeout=5)
            break
        except KafkaException:
            if time.time() > deadline:
                raise
            log.info("chờ Kafka %s sẵn sàng...", settings.KAFKA_BOOTSTRAP)
            time.sleep(3)
    topics = [NewTopic(t, num_partitions=3, replication_factor=1)
              for t in (settings.TOPIC_RAW, settings.TOPIC_ALERTS)]
    for topic, fut in admin.create_topics(topics).items():
        try:
            fut.result()
            log.info("đã tạo topic %s", topic)
        except KafkaException as e:
            if e.args[0].code() != KafkaError.TOPIC_ALREADY_EXISTS:
                log.warning("không tạo được topic %s: %s", topic, e)


def producer() -> Producer:
    return Producer({
        "bootstrap.servers": settings.KAFKA_BOOTSTRAP,
        "linger.ms": 20,
        "compression.type": "lz4",
        "acks": "all",
        "enable.idempotence": True,
    })


def send(p: Producer, topic: str, value: dict[str, Any], key: str | None = None) -> None:
    data = json.dumps(value, ensure_ascii=False, default=str).encode()
    while True:
        try:
            p.produce(topic, data, key=key.encode() if key else None)
            break
        except BufferError:  # hàng đợi nội bộ đầy -> đợi flush bớt
            p.poll(0.5)
    p.poll(0)


def consume(group: str, topics: list[str], poll_timeout: float = 1.0) -> Iterator[dict[str, Any] | None]:
    """Generator trả về message JSON; trả về None khi hết timeout (để caller làm
    việc định kỳ như flush buffer). Offset được auto-commit mỗi 2s."""
    c = Consumer({
        "bootstrap.servers": settings.KAFKA_BOOTSTRAP,
        "group.id": group,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 2000,
    })
    c.subscribe(topics)
    try:
        while True:
            msg = c.poll(poll_timeout)
            if msg is None:
                yield None
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.warning("lỗi Kafka: %s", msg.error())
                continue
            try:
                yield json.loads(msg.value())
            except (ValueError, TypeError):
                log.warning("bỏ qua message không phải JSON")
    finally:
        c.close()
