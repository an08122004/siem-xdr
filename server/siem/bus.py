"""Tiện ích Kafka (message bus trung tâm của pipeline).

    Wazuh (archives/alerts) / syslog --wazuh-manager--> Vector --> [siem.raw] --> analyzer --> [siem.alerts] --> soar
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterator

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer, TopicPartition
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


class Stream:
    """Đọc topic Kafka: lặp ra message JSON, hoặc None khi hết `poll_timeout` (để caller làm việc định kỳ).

    At-least-once: offset KHÔNG tự lưu khi message được đọc ra (enable.auto.offset.store=false), mà chỉ khi caller
    gọi done() — sau khi đã xử lý xong và ghi bền mọi thứ của các message đã đọc (vd analyzer: sau khi bulk ghi ES).
    Trước đây offset tự commit 2 giây/lần trong khi event còn nằm trong bộ đệm analyzer: tiến trình bị dừng / tạo lại
    container đúng lúc đó là mất event. Bây giờ dừng giữa chừng thì lần sau đọc lại (event Wazuh có id cố định nên
    không thành bản ghi trùng)."""

    def __init__(self, group: str, topics: list[str], poll_timeout: float = 1.0):
        self.poll_timeout = poll_timeout
        self.consumer = Consumer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP,
            "group.id": group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,           # commit nền 2 giây/lần, nhưng chỉ các offset đã done()
            "auto.commit.interval.ms": 2000,
            "enable.auto.offset.store": False,
        })
        self.consumer.subscribe(topics)
        self._read: dict[tuple[str, int], int] = {}     # (topic, partition) -> offset kế tiếp cần đọc

    def __iter__(self) -> Iterator[dict[str, Any] | None]:
        try:
            while True:
                msg = self.consumer.poll(self.poll_timeout)
                if msg is None:
                    yield None
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.warning("lỗi Kafka: %s", msg.error())
                    continue
                self._read[(msg.topic(), msg.partition())] = msg.offset() + 1
                try:
                    yield json.loads(msg.value())
                except (ValueError, TypeError):
                    log.warning("bỏ qua message không phải JSON")
        finally:
            self.consumer.close()

    def done(self) -> None:
        """Đánh dấu mọi message đã đọc tới giờ là xử lý xong (commit nền sẽ gửi offset lên Kafka)."""
        if not self._read:
            return
        try:
            self.consumer.store_offsets(offsets=[TopicPartition(t, p, o) for (t, p), o in self._read.items()])
            self._read.clear()
        except KafkaException as e:     # vd partition vừa bị thu hồi khi rebalance: lần sau đọc lại, không mất
            log.warning("không lưu được offset: %s", e)


def consume(group: str, topics: list[str], poll_timeout: float = 1.0) -> Stream:
    return Stream(group, topics, poll_timeout)
