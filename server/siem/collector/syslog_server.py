"""Syslog collector — thu log từ thiết bị KHÔNG cài được agent (firewall F001,
router, switch, Suricata sensor...) qua UDP/TCP 514, đẩy vào Kafka [siem.raw].

Chạy: python -m siem.collector.syslog_server
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from .. import bus, settings

log = logging.getLogger("syslog")
PORT = int(os.getenv("SYSLOG_PORT", "514"))
MAX_LINE = 64 * 1024


class Forwarder:
    def __init__(self) -> None:
        self.producer = bus.producer()
        self.count = 0

    def forward(self, line: str, sender_ip: str) -> None:
        line = line.strip("\x00\r\n ")
        if not line:
            return
        bus.send(self.producer, settings.TOPIC_RAW, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": f"syslog-{sender_ip}",
            "source": "syslog",
            "event_type": "syslog",
            "data": {"message": line[:MAX_LINE], "sender_ip": sender_ip},
        }, key=sender_ip)
        self.count += 1


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, fwd: Forwarder) -> None:
        self.fwd = fwd

    def datagram_received(self, data: bytes, addr) -> None:
        for line in data.decode("utf-8", errors="replace").splitlines():
            self.fwd.forward(line, addr[0])


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, fwd: Forwarder) -> None:
    ip = writer.get_extra_info("peername")[0]
    try:
        while line := await reader.readline():
            fwd.forward(line[:MAX_LINE].decode("utf-8", errors="replace"), ip)
    except (ConnectionError, asyncio.LimitOverrunError, ValueError):
        pass
    finally:
        writer.close()


async def main_async() -> None:
    bus.wait_for_kafka()
    fwd = Forwarder()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UDPProtocol(fwd), local_addr=("0.0.0.0", PORT))
    server = await asyncio.start_server(lambda r, w: handle_tcp(r, w, fwd), "0.0.0.0", PORT, limit=MAX_LINE * 2)
    log.info("syslog collector lắng nghe UDP/TCP %d", PORT)
    async with server:
        while True:
            await asyncio.sleep(5)
            fwd.producer.poll(0)
            fwd.producer.flush(2)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
