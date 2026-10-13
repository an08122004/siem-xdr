"""Feed IOC từ MISP (kho IOC trung tâm, kế hoạch SOC mục Threat intelligence). Tùy chọn: chỉ chạy khi đặt MISP_URL và
secret misp_api_key.

Mỗi MISP_INTERVAL_MINUTES phút gọi POST /attributes/restSearch lấy thuộc tính `to_ids` (MISP đánh dấu "dùng để phát
hiện") của các loại mạng / file, bỏ thuộc tính khớp warninglist (enforceWarninglist: IP / domain phổ biến hợp lệ), rồi
áp HẠN SỐNG theo loại kể từ lần MISP thấy gần nhất (last_seen, không có thì timestamp):
    IP 30 ngày, domain 90 ngày, hash 365 ngày (MISP_TTL_DAYS)
IOC hết hạn không còn khớp (IP bị thu hồi / đổi chủ nhanh, hash thì gần như vĩnh viễn). Tải chạy trong luồng nền:
analyzer không bao giờ chờ MISP; MISP lỗi thì giữ bộ IOC lần trước.
"""
from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from .enrich import IOCSet, Meta

log = logging.getLogger("pipeline.misp")

# loại thuộc tính MISP -> (loại IOC của hệ thống, phần nào của giá trị ghép "a|b")
TYPES: dict[str, list[tuple[str, int]]] = {
    "ip-dst": [("ip", 0)], "ip-src": [("ip", 0)], "ip-dst|port": [("ip", 0)], "ip-src|port": [("ip", 0)],
    "domain": [("domain", 0)], "hostname": [("domain", 0)], "domain|ip": [("domain", 0), ("ip", 1)],
    "md5": [("hash", 0)], "sha1": [("hash", 0)], "sha256": [("hash", 0)],
    "filename|md5": [("hash", 1)], "filename|sha1": [("hash", 1)], "filename|sha256": [("hash", 1)],
}
DEFAULT_TTL = {"ip": 30, "domain": 90, "hash": 365}


def _seen(attr: dict[str, Any]) -> datetime | None:
    for key in ("last_seen", "timestamp"):
        v = attr.get(key)
        if v in (None, ""):
            continue
        try:
            if str(v).isdigit():
                return datetime.fromtimestamp(int(v), timezone.utc)
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except (ValueError, OSError):
            continue
    return None


def parse(attributes: list[dict[str, Any]], ttl: dict[str, int] | None = None,
          now: datetime | None = None) -> list[Meta]:
    """Thuộc tính MISP -> chỉ báo còn hạn (bỏ thuộc tính không to_ids, đã xóa, loại không hỗ trợ, đã hết hạn)."""
    ttl, now = ttl or DEFAULT_TTL, now or datetime.now(timezone.utc)
    out: list[Meta] = []
    for a in attributes:
        if not a.get("to_ids") or a.get("deleted") or str(a.get("type")) not in TYPES:
            continue
        seen = _seen(a)
        parts = str(a.get("value") or "").split("|")
        for kind, idx in TYPES[str(a["type"])]:
            if idx >= len(parts) or not parts[idx].strip():
                continue
            expires = (seen + timedelta(days=ttl[kind])) if seen else None
            if expires and expires < now:
                continue
            event = a.get("Event") or {}
            out.append({"type": kind, "value": parts[idx].strip().lower(), "source": "misp",
                        "description": event.get("info") or a.get("comment") or None,
                        "event": f"misp:event/{a.get('event_id')}" if a.get("event_id") else None,
                        "expires": expires.date().isoformat() if expires else None,
                        "category": a.get("category")})
    return out


class MispFeed:
    def __init__(self, url: str, key: str, ca_file: str = "", verify: bool = True, interval_minutes: float = 60,
                 ttl: dict[str, int] | None = None, timeout: int = 60, opener=None):
        self.url, self.key, self.interval = url.rstrip("/"), key, interval_minutes * 60
        self.ttl = ttl or DEFAULT_TTL
        self.timeout = timeout
        if not verify:
            self.ctx = ssl._create_unverified_context()     # noqa: S323 - chỉ khi người dùng tắt rõ ràng (lab)
        else:
            self.ctx = ssl.create_default_context(cafile=ca_file or None)
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx))
        self._set: IOCSet | None = None
        self._lock = threading.Lock()
        self.last_ok: float | None = None
        self.last_error: str | None = None

    def fetch(self) -> list[dict[str, Any]]:
        days = max(self.ttl.values())
        body = {"returnFormat": "json", "type": list(TYPES), "to_ids": 1, "deleted": False, "published": True,
                "enforceWarninglist": True, "timestamp": f"{days}d", "limit": 100000, "includeEventTags": False}
        req = urllib.request.Request(f"{self.url}/attributes/restSearch", data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": self.key, "Accept": "application/json",
                                              "Content-Type": "application/json"})
        with self.opener(req) as r:
            data = json.loads(r.read() or b"{}")
        return ((data.get("response") or {}).get("Attribute")) or []

    def refresh(self) -> int:
        try:
            items = parse(self.fetch(), self.ttl)
        except Exception as e:  # noqa: BLE001 - MISP lỗi: giữ bộ IOC lần trước
            self.last_error = str(e)[:300]
            log.warning("không tải được IOC từ MISP %s: %s", self.url, e)
            return -1
        s = IOCSet(items)
        with self._lock:
            self._set = s
        self.last_ok, self.last_error = time.time(), None
        log.info("MISP: %s IOC còn hạn", s.counts())
        return len(items)

    def snapshot(self) -> IOCSet | None:
        with self._lock:
            return self._set

    def start(self) -> "MispFeed":
        def loop() -> None:
            while True:
                self.refresh()
                time.sleep(self.interval)
        threading.Thread(target=loop, name="misp-feed", daemon=True).start()
        return self


def from_settings(start: bool = False) -> MispFeed | None:
    from .. import settings
    if not settings.MISP_URL:
        return None
    if not settings.MISP_API_KEY:
        log.error("đặt MISP_URL nhưng secret misp_api_key trống: bỏ qua feed MISP")
        return None
    feed = MispFeed(settings.MISP_URL, settings.MISP_API_KEY, settings.MISP_CA_CERT, settings.MISP_VERIFY_TLS,
                    settings.MISP_INTERVAL_MINUTES, settings.MISP_TTL_DAYS)
    return feed.start() if start else feed
