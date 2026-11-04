"""IOC IP từ MISP -> danh sách CDB của Wazuh (rule TI-001, wazuh/manager/rules/0845-ti.xml).

MispFeed (misp.py) tải IOC mỗi chu kỳ; sau mỗi lần tải xong, MispListSync.push() đổi các IOC loại ip thành text CDB (`khóa:nhãn`
mỗi dòng), đẩy lên danh sách `siem-misp-ip` qua Wazuh API (PUT /lists/files) rồi nạp lại analysisd. Danh sách này TÁCH khỏi danh sách gốc
etc/lists/malicious-ioc/malicious-ip của Wazuh (99915 / 99916 và loại trừ của NET-004 dùng danh sách gốc, R50).

Mọi giá trị đều được kiểm: một IOC sai (hoặc cố ý độc) không được sinh ra dòng làm hỏng danh sách hay làm khớp cả Internet.
Chỉ nhận IPv4 (khóa CDB có dấu `:` nên IPv6 không biểu diễn được) là địa chỉ public (hoặc dải tài liệu RFC 5737 của IOC demo) hoặc mạng public có prefix >= 24.
Wazuh 4.14.8 KHÔNG khớp khóa CIDR trong danh sách CDB (thử: `198.51.100.0/24:` không khớp 198.51.100.9 lẫn 198.51.100.0, cả với
address_match_key), nên mạng được TRIỂN KHAI thành từng địa chỉ (tối đa 256 dòng mỗi mạng); tổng số dòng bị chặn ở MAX_ENTRIES.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
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


def render(items: list[dict[str, Any]]) -> str:
    """IOC (đã qua misp.parse: còn hạn) -> text CDB, mỗi dòng `địa chỉ:misp`, bỏ trùng, có thứ tự cố định. Không có IP hợp lệ thì trả PLACEHOLDER."""
    found = {a for i in items if i.get("type") == "ip" for a in _addresses(i.get("value"))}
    keys = sorted(found, key=lambda a: int(ipaddress.ip_address(a)))
    if len(keys) > MAX_ENTRIES:
        log.warning("%d địa chỉ IOC vượt trần %d: chỉ đẩy %d địa chỉ đầu", len(keys), MAX_ENTRIES, MAX_ENTRIES)
        keys = keys[:MAX_ENTRIES]
    return "".join(f"{k}:misp\n" for k in keys) or PLACEHOLDER + "\n"


def to_cdb(attributes: list[dict[str, Any]], ttl: dict[str, int] | None = None, now: datetime | None = None) -> str:
    """Thuộc tính MISP (đáp án /attributes/restSearch) -> text CDB. Hàm thuần: áp to_ids, hạn sống, loại thuộc tính như MispFeed."""
    return render(misp.parse(attributes, ttl, now))


class MispListSync:
    """Hook của MispFeed.on_refresh: đẩy danh sách lên Wazuh khi nội dung đổi. `api` cần put_list(name, text) và reload()."""

    def __init__(self, api: Any):
        self.api = api
        self._digest: str | None = None

    def push(self, items: list[dict[str, Any]]) -> bool:
        text = render(items)
        digest = hashlib.sha256(text.encode()).hexdigest()
        if digest == self._digest:
            return False
        self.api.put_list(LIST_NAME, text)
        self.api.reload()
        self._digest = digest                  # chỉ nhớ sau khi cả đẩy lẫn nạp lại xong (lỗi thì chu kỳ sau thử lại)
        log.info("đã đẩy %d dòng IOC IP lên Wazuh (%s)", text.count("\n"), LIST_NAME)
        return True
