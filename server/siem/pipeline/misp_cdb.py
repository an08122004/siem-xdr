"""IOC (IP, domain, hash) từ MISP + config/intel -> danh sách CDB của Wazuh (rule TI-001, wazuh/manager/rules/0845-ti.xml).

MispFeed (misp.py) tải IOC mỗi chu kỳ; sau mỗi lần tải xong, MispListSync.push() đổi các IOC loại ip thành text CDB (`khóa:nhãn`
mỗi dòng), đẩy lên danh sách `siem-misp-ip` qua Wazuh API (PUT /lists/files) rồi nạp lại analysisd. Danh sách này TÁCH khỏi danh sách gốc
etc/lists/malicious-ioc/malicious-ip của Wazuh (99915 / 99916 và loại trừ của NET-004 dùng danh sách gốc, R50).
R64: thêm `siem-misp-domain` (IOC loại domain) và `siem-misp-hash` (IOC loại hash: md5 / sha1 / sha256 chung một danh sách), cũng TÁCH khỏi
danh sách gốc malicious-domains / malware-hashes. Khóa CDB khớp CHÍNH XÁC: domain không khớp subdomain (rule YAML cũ có), xem 0845-ti.xml.

Mọi giá trị đều được kiểm: một IOC sai (hoặc cố ý độc) không được sinh ra dòng làm hỏng danh sách hay làm khớp cả Internet.
Chỉ nhận IPv4 (khóa CDB có dấu `:` nên IPv6 không biểu diễn được) là địa chỉ public (hoặc dải tài liệu RFC 5737 của IOC demo) hoặc mạng public có prefix >= 24.
Wazuh 4.14.8 KHÔNG khớp khóa CIDR trong danh sách CDB (thử: `198.51.100.0/24:` không khớp 198.51.100.9 lẫn 198.51.100.0, cả với
address_match_key), nên mạng được TRIỂN KHAI thành từng địa chỉ (tối đa 256 dòng mỗi mạng); tổng số dòng bị chặn ở MAX_ENTRIES.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from datetime import datetime
from typing import Any

from . import misp

log = logging.getLogger("pipeline.misp_cdb")

LIST_NAME = "siem-misp-ip"
# dải tài liệu RFC 5737: không phải "global" nhưng là IOC demo trong config/intel/bad_ips.txt và dữ liệu thử; nhận để IOC cục bộ mẫu hoạt động
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
MIN_PREFIX = 24                       # triển khai từng địa chỉ nên mạng lớn hơn /24 là nhập nhầm / quá rộng (và làm danh sách phình)
MAX_ENTRIES = 100_000                 # trần số dòng của cả danh sách (restSearch của MispFeed cũng giới hạn 100000 thuộc tính)
PLACEHOLDER = "240.0.0.0:empty"       # API Wazuh từ chối file rỗng; 240/4 là dải dự phòng, không bao giờ là nguồn / đích thật
LISTS = {"ip": LIST_NAME, "domain": "siem-misp-domain", "hash": "siem-misp-hash"}      # loại IOC -> tên danh sách
PLACEHOLDERS = {"ip": PLACEHOLDER, "domain": "placeholder.invalid:empty", "hash": "0" * 32 + ":empty"}   # .invalid (RFC 2606) và hash toàn 0 không bao giờ là IOC thật
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")        # md5 / sha1 / sha256


def _addresses(value: Any) -> list[str]:
    """Giá trị IOC -> các địa chỉ IPv4 cần đưa vào danh sách (host: 1 địa chỉ; mạng: mọi địa chỉ), hoặc [] nếu không hợp lệ / không nên đưa vào."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=True)     # strict: "1.2.3.4/24" (bit máy) bị loại, không tự nới rộng
    except ValueError:
        return []
    if net.version != 4 or net.prefixlen < MIN_PREFIX or net.is_multicast:
        return []
    if not (net.network_address.is_global and net.broadcast_address.is_global) and not any(net.subnet_of(d) for d in DOC_NETS):
        return []
    return [str(a) for a in net]


def _domain(value: Any) -> list[str]:
    """Domain IOC -> [tên chữ thường dạng ASCII (IDN đổi sang punycode)] nếu hợp lệ, ngược lại []: >= 2 nhãn, nhãn [a-z0-9-] không đầu / cuối `-`, TLD không toàn số
    (khỏi lẫn IP), không `*` / khoảng trắng / `:` / xuống dòng. Dấu `.` cuối (FQDN) được bỏ."""
    v = str(value).strip().lower()
    v = v[:-1] if v.endswith(".") else v
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return []
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return []
    return [v]


def _hash(value: Any) -> list[str]:
    v = str(value).strip().lower()
    return [v] if _HASH.match(v) else []


_NORMALIZE = {"ip": _addresses, "domain": _domain, "hash": _hash}


def render(items: list[dict[str, Any]], kind: str = "ip") -> str:
    """IOC (đã qua misp.parse: còn hạn) loại `kind` -> text CDB, mỗi dòng `khóa:misp`, bỏ trùng, có thứ tự cố định. Không có giá trị hợp lệ thì trả dòng giữ chỗ."""
    found = {a for i in items if i.get("type") == kind for a in _NORMALIZE[kind](i.get("value"))}
    keys = sorted(found, key=lambda a: int(ipaddress.ip_address(a))) if kind == "ip" else sorted(found)
    if len(keys) > MAX_ENTRIES:
        log.warning("%d địa chỉ IOC vượt trần %d: chỉ đẩy %d địa chỉ đầu", len(keys), MAX_ENTRIES, MAX_ENTRIES)
        keys = keys[:MAX_ENTRIES]
    return "".join(f"{k}:misp\n" for k in keys) or PLACEHOLDERS[kind] + "\n"


def to_cdb(attributes: list[dict[str, Any]], ttl: dict[str, int] | None = None, now: datetime | None = None, kind: str = "ip") -> str:
    """Thuộc tính MISP (đáp án /attributes/restSearch) -> text CDB. Hàm thuần: áp to_ids, hạn sống, loại thuộc tính như MispFeed."""
    return render(misp.parse(attributes, ttl, now), kind)


class MispListSync:
    """Hook của MispFeed.on_refresh: đẩy cả ba danh sách (ip / domain / hash) lên Wazuh khi nội dung đổi. `api` cần put_list(name, text) và reload()."""

    def __init__(self, api: Any):
        self.api = api
        self._digest: dict[str, str] = {}

    def push(self, items: list[dict[str, Any]]) -> bool:
        changed: dict[str, tuple[str, str]] = {}
        for kind, name in LISTS.items():
            text = render(items, kind)
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest != self._digest.get(name):
                changed[name] = (text, digest)
        if not changed:
            return False
        for name, (text, _) in changed.items():
            self.api.put_list(name, text)
        self.api.reload()
        for name, (text, digest) in changed.items():
            self._digest[name] = digest                  # chỉ nhớ sau khi cả đẩy lẫn nạp lại xong (lỗi thì chu kỳ sau thử lại cả nhóm đổi)
            log.info("đã đẩy %d dòng IOC lên Wazuh (%s)", text.count("\n"), name)
        return True
