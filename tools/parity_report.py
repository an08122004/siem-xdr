"""Báo cáo song song YAML <-> XML (kế hoạch Task 13): mỗi mã rule cũ, alert của rule YAML so với alert của rule XML
Wazuh (rule.legacy_id, kể cả alert chạy bóng) có cùng tham chiếu tới event nào.

    python tools/parity_report.py --since 2026-11-02T00:00:00+00:00        # ghi build/parity.md
    python tools/parity_report.py --since ... --out - --index siem-alerts

Chạy từ thư mục gốc project khi stack đang chạy; chỉ ĐỌC siem-alerts (qua helper `es` của tools/es_snapshot.py).
Ghép theo event.id nằm trong related_events của alert. Rule tần suất YAML bắn ở event thứ N còn rule XML có thể bắn ở
event khác: event lệch đó hiện ở only_yaml / only_xml chứ không bị gộp lại; đọc kèm số alert (cột yaml / xml).
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def _ts(s: str) -> datetime:
    d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _legacy_codes(a: dict) -> tuple[str, list[str]]:
    """('yaml', [mã]) cho alert rule YAML, ('xml', [mã...]) cho alert Wazuh có mã cũ, ('', []) cho loại khác."""
    rule, src = a.get("rule") or {}, (a.get("alert") or {}).get("source")
    if src == "rule" and rule.get("id"):
        return "yaml", [rule["id"]]
    if src == "wazuh":
        ids = rule.get("legacy_ids") or ([rule["legacy_id"]] if rule.get("legacy_id") else [])
        return ("xml", list(ids)) if ids else ("", [])
    return "", []


def parity(alerts: list[dict], since: str) -> dict[str, dict]:
    t0, seen = _ts(since), {}
    for a in alerts:
        side, codes = _legacy_codes(a)
        if not side or _ts(a.get("@timestamp") or "1970-01-01T00:00:00+00:00") < t0:
            continue
        for c in codes:
            d = seen.setdefault(c, {"yaml": 0, "xml": 0, "ev": {"yaml": set(), "xml": set()}})
            d[side] += 1
            d["ev"][side].update(e for e in a.get("related_events") or [] if e)
    return {c: {"yaml": d["yaml"], "xml": d["xml"], "matched": len(d["ev"]["yaml"] & d["ev"]["xml"]),
                "only_yaml": sorted(d["ev"]["yaml"] - d["ev"]["xml"]),
                "only_xml": sorted(d["ev"]["xml"] - d["ev"]["yaml"])}
            for c, d in sorted(seen.items())}


def markdown(report: dict[str, dict], since: str, examples: int = 3) -> str:
    out = [f"# Đối chiếu alert YAML với XML (từ {since})", "",
           "`matched` = số event cả hai bên cùng tham chiếu; `only_*` = số event chỉ một bên có.", "",
           "| Mã | yaml | xml | matched | only_yaml | only_xml | ví dụ event chỉ-YAML / chỉ-XML |", "|---|---|---|---|---|---|---|"]
    for c, r in report.items():
        out.append(f"| {c} | {r['yaml']} | {r['xml']} | {r['matched']} | {len(r['only_yaml'])} | "
                   f"{len(r['only_xml'])} | {', '.join(r['only_yaml'][:examples]) or '-'} / "
                   f"{', '.join(r['only_xml'][:examples]) or '-'} |")
    return "\n".join(out) + "\n"


def fetch(index: str, since: str, size: int = 10000) -> list[dict]:
    from es_snapshot import es      # chỉ đọc: _search, không ghi
    q = {"size": size, "sort": [{"@timestamp": "asc"}], "_source": ["@timestamp", "alert", "rule", "related_events"],
         "query": {"range": {"@timestamp": {"gte": since}}}}
    return [h["_source"] for h in es("POST", f"/{index}/_search", q).get("hits", {}).get("hits", [])]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--since", required=True, help="ISO 8601, bỏ alert cũ hơn mốc này")
    ap.add_argument("--index", default="siem-alerts")
    ap.add_argument("--out", default="build/parity.md", help="'-' = in ra màn hình")
    a = ap.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    md = markdown(parity(fetch(a.index, a.since), a.since), a.since)
    if a.out == "-":
        print(md)
    else:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(md, encoding="utf-8")
        print(f"đã ghi {a.out}")


if __name__ == "__main__":
    main()
