"""Báo cáo song song YAML <-> XML (kế hoạch Task 13): mỗi mã rule cũ, alert của rule YAML so với alert của rule XML
Wazuh (rule.legacy_id, kể cả alert chạy bóng) có cùng tham chiếu tới event nào.

    python tools/parity_report.py --since 2026-11-02T00:00:00+00:00        # ghi build/parity.md
    python tools/parity_report.py --since ... --out - --index siem-alerts

Chạy từ thư mục CHÍNH của project (không phải worktree) khi stack đang chạy: `docker compose exec` không có `-p`, nên
dựa vào .env ở đó. Chỉ ĐỌC siem-alerts (helper `es` của tools/es_snapshot.py, chỉ gọi `_search`), phân trang search_after.
Ghép theo event KÍCH HOẠT của alert (related_events[-1]: rules.py thêm event hiện tại vào cuối danh sách, còn rule
Wazuh chỉ có đúng một event), không theo cả danh sách event đóng góp của rule ngưỡng/chuỗi. Rule tần suất YAML bắn ở event thứ N còn rule XML có thể bắn ở
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
            if trigger := (a.get("related_events") or [None])[-1]:
                d["ev"][side].add(trigger)
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


def fetch(index: str, since: str, page: int = 5000, search=None) -> list[dict]:
    """Đọc hết alert từ `since`, phân trang search_after (sort @timestamp + alert.id làm tiebreaker)."""
    if search is None:
        from es_snapshot import es      # chỉ đọc: _search, không ghi
        search = lambda body: es("POST", f"/{index}/_search", body)  # noqa: E731
    body = {"size": page, "sort": [{"@timestamp": "asc"}, {"alert.id": "asc"}],
            "_source": ["@timestamp", "alert", "rule", "related_events"],
            "query": {"range": {"@timestamp": {"gte": since}}}}
    out: list[dict] = []
    while hits := search(body).get("hits", {}).get("hits", []):
        out += [h["_source"] for h in hits]
        if len(hits) < page:
            break
        body = {**body, "search_after": hits[-1]["sort"]}
    return out


def _iso(s: str) -> str:
    try:
        _ts(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"không phải thời điểm ISO 8601: {s!r}") from None
    return s


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--since", required=True, type=_iso, help="ISO 8601, bỏ alert cũ hơn mốc này")
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
