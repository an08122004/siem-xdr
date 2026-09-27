"""Làm giàu (enrich) event sau khi chuẩn hóa:

- Threat Intelligence: đối chiếu IP / domain / hash với danh sách IOC
  (config/intel/*.txt) -> gắn threat.indicator.*
- Asset: gắn thông tin tài sản (ID, loại, mức độ quan trọng) từ config/assets.yml
- Phân loại IP: private/public/loopback -> source.ip_scope
"""
from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from .normalize import Doc, get, put

log = logging.getLogger(__name__)

_IOC_FILES = {"ip": "bad_ips.txt", "domain": "bad_domains.txt", "hash": "bad_hashes.txt"}


class ThreatIntel:
    def __init__(self, intel_dir: Path):
        self.dir = intel_dir
        self.iocs: dict[str, set[str]] = {k: set() for k in _IOC_FILES}
        self.networks: list[ipaddress._BaseNetwork] = []
        self._mtime = 0.0
        self.reload()

    def reload(self) -> None:
        for kind, fname in _IOC_FILES.items():
            path = self.dir / fname
            if not path.exists():
                continue
            values = set()
            for line in path.read_text(encoding="utf-8").splitlines():
                v = line.split("#", 1)[0].strip().lower()
                if v:
                    values.add(v)
            self.iocs[kind] = values
        self.networks = []
        for v in list(self.iocs["ip"]):
            if "/" in v:
                try:
                    self.networks.append(ipaddress.ip_network(v, strict=False))
                except ValueError:
                    pass
        self._mtime = self._dir_mtime()
        log.info("threat intel: %s", {k: len(v) for k, v in self.iocs.items()})

    def _dir_mtime(self) -> float:
        try:
            return max((p.stat().st_mtime for p in self.dir.glob("*.txt")), default=0.0)
        except OSError:
            return 0.0

    def maybe_reload(self) -> None:
        if self._dir_mtime() > self._mtime:
            self.reload()

    def match_ip(self, ip: str | None) -> bool:
        if not ip:
            return False
        if ip.lower() in self.iocs["ip"]:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.networks)

    def match_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        d = domain.lower().rstrip(".")
        parts = d.split(".")
        # khớp cả subdomain: a.b.evil.com khớp evil.com
        return any(".".join(parts[i:]) in self.iocs["domain"] for i in range(len(parts) - 1))

    def enrich(self, doc: Doc) -> None:
        for field in ("source.ip", "destination.ip"):
            if self.match_ip(get(doc, field)):
                _hit(doc, "ip", get(doc, field), field)
                return
        for field in ("dns.question.name", "url.domain", "destination.domain"):
            if self.match_domain(get(doc, field)):
                _hit(doc, "domain", get(doc, field), field)
                return
        hashes = get(doc, "process.hash") or {}
        for h in hashes.values() if isinstance(hashes, dict) else []:
            if h in self.iocs["hash"]:
                _hit(doc, "hash", h, "process.hash")
                return


def _hit(doc: Doc, kind: str, value: Any, field: str) -> None:
    put(doc, "threat.indicator.type", kind)
    put(doc, "threat.indicator.value", value)
    put(doc, "threat.indicator.field", field)
    put(doc, "threat.matched", True)


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
    def __init__(self, config_dir: Path):
        self.ti = ThreatIntel(config_dir / "intel")
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
    return Enricher(Path(os.getenv("CONFIG_DIR", settings.CONFIG_DIR)))
