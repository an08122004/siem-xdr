"""In danh sách CDB (IOC IP) từ đáp án MISP /attributes/restSearch, để xem / kiểm trước khi SOAR đẩy lên Wazuh.

    python tools/misp_to_cdb.py restsearch.json > siem-misp-ip       # hoặc đọc stdin: ... | python tools/misp_to_cdb.py -

Logic nằm ở server/siem/pipeline/misp_cdb.py (SOAR dùng chính hàm này mỗi chu kỳ đồng bộ MISP). Không gọi mạng, không ghi vào Wazuh.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
from siem.pipeline.misp_cdb import to_cdb  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    raw = sys.stdin.read() if argv[1] == "-" else Path(argv[1]).read_text(encoding="utf-8")
    data = json.loads(raw)
    attrs = (data.get("response") or {}).get("Attribute", []) if isinstance(data, dict) else data
    sys.stdout.write(to_cdb(attrs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
