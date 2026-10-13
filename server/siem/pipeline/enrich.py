"""Làm giàu (enrich) event sau khi chuẩn hóa:

- Threat Intelligence: đối chiếu IP / domain / hash với danh sách IOC (config/intel/*.txt, kèm feed MISP nếu cấu hình
  MISP_URL, pipeline/misp.py) -> gắn threat.indicator.* (kèm nguồn, mô tả, hạn). IOC có vòng đời: dòng trong file ghi
  `hết hạn: YYYY-MM-DD` (hoặc `expires=YYYY-MM-DD`) trong phần chú thích thì sau ngày đó không còn khớp; IOC từ MISP
  hết hạn theo loại (IP 30 ngày, domain 90 ngày, hash 1 năm kể từ lần thấy gần nhất).
- Asset: gắn thông tin tài sản (ID, loại, mức độ quan trọng) từ config/assets.yml
- Phân loại IP: private/public/loopback -> source.ip_scope
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .normalize import Doc, get, put

log = logging.getLogger(__name__)

_IOC_FILES = {"ip": "bad_ips.txt", "domain": "bad_domains.txt", "hash": "bad_hashes.txt"}
_EXPIRES = re.compile(r"(?:hết hạn|het han|expires?)\s*[:=]?\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)
Meta = dict[str, Any]          # {"type", "value", "source", "description", "expires"}


def parse_line(line: str, kind: str, today: date | None = None) -> Meta | None:
    """Một dòng file IOC -> chỉ báo (None: dòng trống / chú thích / đã hết hạn). Giá trị trước dấu #, phần sau là mô tả."""
    value, _, note = line.partition("#")
    value = value.strip().lower()
    if not value:
        return None
    note = note.strip()
    m = _EXPIRES.search(note)
    expires = m.group(1) if m else None
    if expires and date.fromisoformat(expires) < (today or datetime.now(timezone.utc).date()):
        return None
    return {"type": kind, "value": value, "source": "local", "description": note or None, "expires": expires}


class IOCSet:
    """Chỉ báo theo loại (ip / domain / hash) và dải IP (CIDR), mỗi giá trị kèm metadata."""

    def __init__(self, items: list[Meta] | None = None):
        self.values: dict[str, dict[str, Meta]] = {k: {} for k in _IOC_FILES}
        self.networks: list[tuple[Any, Meta]] = []
        for m in items or []:
            self.add(m)

    def add(self, m: Meta) -> None:
        kind, v = m["type"], m["value"]
        if kind == "ip" and "/" in v:
            try:
                self.networks.append((ipaddress.ip_network(v, strict=False), m))
            except ValueError:
                return
        self.values.setdefault(kind, {})[v] = m

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.values.items()}

    def all(self) -> list[Meta]:
        return [m for vals in self.values.values() for m in vals.values()]

    def ip(self, ip: str) -> Meta | None:
        if (m := self.values["ip"].get(ip.lower())):
            return m
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((m for n, m in self.networks if addr.version == n.version and addr in n), None)

    def domain(self, domain: str) -> Meta | None:
        parts = domain.lower().rstrip(".").split(".")
        # khớp cả subdomain: a.b.evil.com khớp evil.com
        return next((m for i in range(len(parts) - 1) if (m := self.values["domain"].get(".".join(parts[i:])))), None)

    def hash(self, h: str) -> Meta | None:
        return self.values["hash"].get(str(h).lower())


class ThreatIntel:
    def __init__(self, intel_dir: Path, feed=None):
        self.dir = intel_dir
        self.feed = feed                                  # pipeline/misp.py MispFeed (tùy chọn): .snapshot() -> IOCSet
        self.local = IOCSet()
        self._mtime = 0.0
        self._next_expiry: date | None = None
        self.reload()

    @property
    def iocs(self) -> dict[str, set[str]]:
        """Tập giá trị IOC cục bộ theo loại (giữ cho mã cũ / test)."""
        return {k: set(v) for k, v in self.local.values.items()}

    def reload(self) -> None:
        items = []
        for kind, fname in _IOC_FILES.items():
            path = self.dir / fname
            if path.exists():
                items += [m for line in path.read_text(encoding="utf-8").splitlines() if (m := parse_line(line, kind))]
        self.local = IOCSet(items)
        expiries = [date.fromisoformat(m["expires"]) for m in items if m.get("expires")]
        self._next_expiry = min(expiries) if expiries else None
        self._mtime = self._dir_mtime()
        log.info("threat intel cục bộ: %s", self.local.counts())

    def _dir_mtime(self) -> float:
        try:
            return max((p.stat().st_mtime for p in self.dir.glob("*.txt")), default=0.0)
        except OSError:
            return 0.0

    def maybe_reload(self) -> None:
        """File đổi, hoặc có IOC vừa qua hạn -> nạp lại."""
        expired = self._next_expiry is not None and self._next_expiry < datetime.now(timezone.utc).date()
        if expired or self._dir_mtime() > self._mtime:
            self.reload()

    def sets(self) -> list[IOCSet]:
        out = [self.local]
        if self.feed is not None and (snap := self.feed.snapshot()) is not None:
            out.append(snap)
        return out

    def indicators(self) -> list[Meta]:
        """Mọi IOC đang hiệu lực (cục bộ + feed): SOAR dò ngược log cũ khi có IOC mới (soar/retrohunt.py)."""
        seen: dict[tuple[str, str], Meta] = {}
        for s in self.sets():
            for m in s.all():
                seen.setdefault((m["type"], m["value"]), m)
        return list(seen.values())

    def match_ip(self, ip: str | None) -> Meta | None:
        return next((m for s in self.sets() if (m := s.ip(ip))), None) if ip else None

    def match_domain(self, domain: str | None) -> Meta | None:
        return next((m for s in self.sets() if (m := s.domain(domain))), None) if domain else None

    def match_hash(self, h: str | None) -> Meta | None:
        return next((m for s in self.sets() if (m := s.hash(h))), None) if h else None

    def enrich(self, doc: Doc) -> None:
        for field in ("source.ip", "destination.ip"):
            if (m := self.match_ip(get(doc, field))):
                _hit(doc, "ip", get(doc, field), field, m)
                return
        for field in ("dns.question.name", "url.domain", "destination.domain"):
            if (m := self.match_domain(get(doc, field))):
                _hit(doc, "domain", get(doc, field), field, m)
                return
        hashes = get(doc, "process.hash") or {}
        for h in hashes.values() if isinstance(hashes, dict) else []:
            if (m := self.match_hash(h)):
                _hit(doc, "hash", h, "process.hash", m)
                return


def _hit(doc: Doc, kind: str, value: Any, field: str, meta: Meta | None = None) -> None:
    put(doc, "threat.indicator.type", kind)
    put(doc, "threat.indicator.value", value)
    put(doc, "threat.indicator.field", field)
    put(doc, "threat.matched", True)
    if meta:
        put(doc, "threat.indicator.provider", meta.get("source"))
        if meta.get("description"):
            put(doc, "threat.indicator.description", str(meta["description"])[:300])
        if meta.get("expires"):
            put(doc, "threat.indicator.expires", meta["expires"])
        if meta.get("event"):
            put(doc, "threat.indicator.reference", meta["event"])
        if meta.get("value") != str(value).lower():
            put(doc, "threat.indicator.matched", meta.get("value"))   # dải CIDR / domain cha đã khớp


class AssetDB:
    """Tra cứu tài sản theo agent_id / hostname / IP (config/assets.yml)."""

    def __init__(self, path: Path):
        self.by_key: dict[str, dict[str, Any]] = {}
        if path.exists():
            items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            for a in items:
                for key in [a.get("agent_id"), a.get("hostname"), *(a.get("ips") or [])]:
                    if key:
                        self.by_key[str(key).lower()] = a
        log.info("asset DB: %d khóa tra cứu", len(self.by_key))

    def enrich(self, doc: Doc) -> None:
        for key in (get(doc, "agent.id"), get(doc, "host.name"), get(doc, "observer.ip")):
            a = self.by_key.get(str(key).lower()) if key else None
            if a:
                put(doc, "asset.id", a.get("id"))
                put(doc, "asset.name", a.get("name"))
                put(doc, "asset.type", a.get("type"))
                put(doc, "asset.criticality", a.get("criticality", "medium"))
                return


# Chỉ coi là "private" các dải nội bộ thật sự (RFC1918, CGNAT, link-local, ULA).
# Không dùng ipaddress.is_private vì nó coi cả dải TEST-NET/documentation là private.
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def ip_scope(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_loopback:
        return "loopback"
    if any(a in n for n in _PRIVATE_NETS if n.version == a.version):
        return "private"
    return "public"


class Enricher:
    def __init__(self, config_dir: Path, feed=None):
        self.ti = ThreatIntel(config_dir / "intel", feed=feed)
        self.assets = AssetDB(config_dir / "assets.yml")
        self._count = 0

    def enrich(self, doc: Doc) -> Doc:
        self._count += 1
        if self._count % 5000 == 0:
            self.ti.maybe_reload()
        put(doc, "source.ip_scope", ip_scope(get(doc, "source.ip")))
        put(doc, "destination.ip_scope", ip_scope(get(doc, "destination.ip")))
        self.ti.enrich(doc)
        self.assets.enrich(doc)
        return doc


def default_enricher() -> Enricher:
    from .. import settings
    from .misp import from_settings
    return Enricher(Path(os.getenv("CONFIG_DIR", settings.CONFIG_DIR)), feed=from_settings(start=True))
