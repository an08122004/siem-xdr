"""Đánh giá và khởi tạo offline model ML bất thường (server/siem/detection/ml.py) từ event trong Elasticsearch.

Chạy từ thư mục stack THẬT (nơi .env ghim project siem-xdr; es_snapshot dùng `docker compose exec`), chỉ ĐỌC ES:

    cd D:/GSANM/BTL/siem-xdr && python <worktree>/tools/ml_eval.py train --from ISO --to ISO --out ml-state.json
    python .../tools/ml_eval.py eval --train-from ISO --train-to ISO --test-from ISO --test-to ISO \
        --attacks attacks.jsonl --out REPORT.md [--scores-csv scores.csv] [--target-fp 0.005]

`train` ghi file trạng thái version 2 bằng chính AnomalyDetector.save() (chép vào volume của analyzer).
`eval` học trên khoảng học, chấm khoảng thử, báo bắt được kịch bản nào và tỉ lệ báo nhầm trên người dùng bình thường;
`--scores-csv` ghi thêm điểm của MỌI cửa sổ thử (vẽ histogram điểm, ROC / PR).
`label` (CHỈ cho lab, lệnh duy nhất GHI ES): đóng alert ML chưa có kết luận bằng nhãn của attacks.jsonl, thay cho analyst:
IP kịch bản tấn công trong khoảng chạy thì true_positive, dải người dùng mô phỏng thì false_positive. AI worker lấy alert
ML true_positive làm nguồn khoảng trống gap-ml (rule tần suất):

    python .../tools/ml_eval.py label --attacks attacks.jsonl [--since ISO] [--normal-ips 10.10.1.40-59]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "server"))      # `siem` của worktree chứa file này, không phải của thư mục đang đứng
sys.path.insert(0, str(HERE))
from siem.detection import ml  # noqa: E402

PAGE = 5000


def ip_range(spec: str) -> list[str]:
    base, _, last = spec.rpartition("-")
    head, _, first = base.rpartition(".")
    return [f"{head}.{i}" for i in range(int(first), int(last) + 1)]


def to_epoch(iso: str) -> float:
    d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


# ---------------------------------------------------------------- đọc ES (chỉ search)
def _search(index: str, query: dict, es=None, tie: str = "event.id"):
    if es is None:
        from es_snapshot import es
    after = None
    while True:
        body = {"size": PAGE, "query": query, "sort": [{"@timestamp": "asc"}, {tie: "asc"}],
                **({"search_after": after} if after else {})}
        hits = es("POST", f"/{index}/_search?ignore_unavailable=true", body).get("hits", {}).get("hits", [])
        yield from hits
        if len(hits) < PAGE:
            return
        after = hits[-1]["sort"]


def fetch_events(t0: float, t1: float, es=None):
    rng = {"range": {"@timestamp": {"gte": _iso(t0), "lt": _iso(t1)}}}
    for h in _search("siem-events-*", rng, es):
        doc = h["_source"]
        yield doc, to_epoch(doc["@timestamp"])


def fetch_alerts(t0: float, t1: float, es=None) -> list[tuple[str, float]]:
    """(IP, thời điểm) của alert Wazuh KHÔNG bóng."""
    q = {"bool": {"filter": [{"term": {"alert.source": "wazuh"}}, {"range": {"@timestamp": {"gte": _iso(t0), "lt": _iso(t1)}}}],
                  "must_not": [{"term": {"alert.shadow": True}}]}}
    out = []
    for h in _search("siem-alerts", q, es, "alert.id"):
        s = h["_source"]
        ip = (s.get("source") or {}).get("ip")
        if ip:
            out.append((ip, to_epoch(s["@timestamp"])))
    return out


# ---------------------------------------------------------------- logic thuần
def training_vectors(events, exclude: set[str], alerted: dict[str, list[float]] | None = None) -> dict[str, list[list[float]]]:
    """events: (doc, ts). Bỏ IP trong `exclude` và cửa sổ có alert Wazuh thật của IP đó (alerted: IP -> [ts])."""
    alerted = alerted or {}
    events = [(d, t) for d, t in events if (d.get("source") or {}).get("ip") not in exclude]
    out = {}
    for name, spec in ml.SPECS.items():
        out[name] = [v for ip, start, v, _ in ml.windows_from_events(events, spec)
                     if not any(start <= t < start + spec.window for t in alerted.get(ip, ()))]
    return out


def lab_verdict(ip: str, model: str, t: float, scenarios: list[dict], normal_ips: set[str]) -> str | None:
    """Kết luận cho alert ML ở thời điểm t: cùng IP với kịch bản tấn công và nằm trong [start - 1 cửa sổ, end + 1 cửa sổ]
    (như match) thì true_positive; IP người dùng mô phỏng thì false_positive; còn lại để analyst."""
    w = ml.SPECS[model].window
    if any(sc["ip"] == ip and to_epoch(sc["start"]) - w <= t <= to_epoch(sc["end"]) + w for sc in scenarios):
        return "true_positive"
    return "false_positive" if ip in normal_ips else None


def match(anomalies: list, scenarios: list[dict]) -> dict[str, dict]:
    """Anomaly khớp kịch bản khi cùng IP và cửa sổ nằm trong [start - 1 cửa sổ, end + 1 cửa sổ]."""
    out = {}
    for sc in scenarios:
        t0, t1 = to_epoch(sc["start"]), to_epoch(sc["end"])
        hits = [a for a in anomalies if a.entity == sc["ip"]
                and t0 - ml.SPECS[a.model].window <= a.window_start <= t1 + ml.SPECS[a.model].window]
        hits.sort(key=lambda a: a.window_start)
        key, n = sc["scenario"], 2
        while key in out:
            key, n = f"{sc['scenario']}#{n}", n + 1
        out[key] = {"detected": bool(hits), "ip": sc["ip"], "models": sorted({a.model for a in hits}),
                    "delay": max(0.0, hits[0].window_start - t0) if hits else None,
                    "top": ml.explain(hits[0]) if hits else ""}
    return out


def fp_rate(anomalies: list, normal_ips: set[str], scored_windows: int) -> float:
    return sum(a.entity in normal_ips for a in anomalies) / scored_windows if scored_windows else 0.0


def score_rows(det: ml.AnomalyDetector, events, attack: set[str], normal: set[str]) -> list[list]:
    """Điểm Isolation Forest của mọi cửa sổ thử, kể cả cửa sổ không bị gắn cờ (flush chỉ trả cửa sổ dưới ngưỡng).
    Model chưa học xong (forest None) thì bỏ qua."""
    rows = []
    for name, spec in ml.SPECS.items():
        m = det.models[name]
        wins = ml.windows_from_events(events, spec)
        if m.forest is None or not wins:
            continue
        scores = m.forest.decision_function(ml._matrix(spec, [v for _, _, v, _ in wins]))
        for (ip, start, _, _), s in zip(wins, scores):
            label = "attack" if ip in attack else "normal" if ip in normal else "other"
            rows.append([name, ip, _iso(start), round(float(s), 5), round(m.threshold, 5), label, int(s < m.threshold)])
    return rows


# ---------------------------------------------------------------- lệnh
def _seeded(vecs, t_from, t_to, state_path=None, **kw) -> ml.AnomalyDetector:
    det = ml.AnomalyDetector(state_path, **kw)
    for name, v in vecs.items():
        det.seed(name, v, t_from)
        det.models[name].watermark = t_to        # event cũ hơn khoảng học đã được tính, analyzer không học lại
    return det


def _load(t0, t1):
    alerts = fetch_alerts(t0, t1)
    al: dict[str, list[float]] = {}
    for ip, t in alerts:
        al.setdefault(ip, []).append(t)
    return list(fetch_events(t0, t1)), alerts, al


def cmd_train(a) -> None:
    t0, t1 = to_epoch(a.from_), to_epoch(a.to)
    events, _, al = _load(t0, t1)
    vecs = training_vectors(events, set(ip_range(a.exclude_ips)), al)
    det = _seeded(vecs, t0, t1, Path(a.out))
    det.save()
    print(f"{len(events)} event -> " + ", ".join(f"{n}: {len(v)} cửa sổ" for n, v in vecs.items()) + f"; đã ghi {a.out}")


def cmd_eval(a) -> None:
    tr0, tr1, te0, te1 = (to_epoch(x) for x in (a.train_from, a.train_to, a.test_from, a.test_to))
    scenarios = [json.loads(x) for x in Path(a.attacks).read_text(encoding="utf-8").splitlines() if x.strip()]
    scenarios = [s for s in scenarios if te0 <= to_epoch(s["start"]) < te1]
    atk, normal = set(ip_range(a.exclude_ips)), set(ip_range(a.normal_ips))
    train_ev, _, al = _load(tr0, tr1)
    vecs = training_vectors(train_ev, atk, al)
    # cooldown 0 và không fit lại: mỗi cửa sổ bất thường được đếm, model không bị học thêm từ khoảng thử
    det = _seeded(vecs, tr0, tr1, learn_hours=0, min_windows=1, cooldown=0, retrain_hours=1e9, target_fp=a.target_fp)
    test_ev, alerts, _ = _load(te0, te1)
    found, last = [], tr1
    for doc, ts in test_ev:
        det.add(doc, ts)
        if ts - last > 60:
            found += det.flush(ts)
            last = ts
    found += det.flush(te1) + det.flush(te1 + ml.IDLE_SECONDS) + det.flush(te1 + 2 * ml.IDLE_SECONDS)
    res = match(found, scenarios)
    scored = {n: sum(1 for ip, *_ in ml.windows_from_events(test_ev, s) if ip in normal) for n, s in ml.SPECS.items()}
    st = det.status()

    def fmt(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = ["# Đánh giá ML bất thường", "", f"- Học: {fmt(tr0)} .. {fmt(tr1)}", f"- Thử: {fmt(te0)} .. {fmt(te1)}", "",
             "| Model | Cửa sổ học | Ngưỡng | Pha | Cửa sổ thử (người dùng thường) |", "|---|---|---|---|---|"]
    for n in ml.SPECS:
        th = st[n]["threshold"]
        lines.append(f"| {n} | {len(vecs[n])} | {'-' if th is None else format(th, '.3f')} | {st[n]['phase']} | {scored[n]} |")
    lines += ["", "| Kịch bản | IP | Bắt được? | Sau bao lâu | Đặc trưng nổi bật | Rule Wazuh bắt? |", "|---|---|---|---|---|---|"]
    for sc, (k, r) in zip(scenarios, res.items()):
        s0, s1 = to_epoch(sc["start"]), to_epoch(sc["end"])
        w = "có" if any(i == sc["ip"] and s0 - 60 <= t <= s1 + 60 for i, t in alerts) else "không"
        d = "-" if r["delay"] is None else f"{int(r['delay'])} s"
        lines.append(f"| {k} | {r['ip']} | {'CÓ' if r['detected'] else 'không'} | {d} | {r['top'] or '-'} | {w} |")
    tot = sum(scored.values())
    nfa = sum(x.entity in normal for x in found)
    lines += ["", f"Báo nhầm trên {a.normal_ips}: {nfa} / {tot} cửa sổ = {fp_rate(found, normal, tot):.4f}"]
    Path(a.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if a.scores_csv:
        with open(a.scores_csv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([["model", "ip", "window_start", "score", "threshold", "label", "flagged"],
                                     *score_rows(det, test_ev, atk, normal)])


def cmd_label(a) -> None:
    from es_snapshot import es
    scenarios = [json.loads(x) for x in Path(a.attacks).read_text(encoding="utf-8").splitlines() if x.strip()]
    normal = set(ip_range(a.normal_ips))
    # chỉ alert ML CHƯA có kết luận: không ghi đè kết luận của analyst
    q = {"bool": {"filter": [{"terms": {"rule.id": ["ML-WEB", "ML-AUTH"]}}, {"range": {"@timestamp": {"gte": a.since}}}],
                  "must_not": [{"exists": {"field": "alert.verdict"}}]}}
    now, done = datetime.now(timezone.utc).isoformat(), Counter()
    for h in list(_search("siem-alerts", q, tie="alert.id")):
        s = h["_source"]
        al, ip, model = s.get("alert") or {}, (s.get("source") or {}).get("ip"), (s.get("ml") or {}).get("model")
        verdict = lab_verdict(ip, model, to_epoch(s.get("event_time") or s["@timestamp"]), scenarios, normal) \
            if ip and model in ml.SPECS else None
        if not verdict:
            done["để analyst"] += 1
            continue
        status = "false_positive" if verdict == "false_positive" else "closed"     # như api.closing
        note = {"at": now, "by": "lab-attacks", "text": f"trạng thái: {al.get('status')} -> {status} (nhãn lab {verdict}, "
                                                        f"{Path(a.attacks).name})"}
        es("POST", f"/siem-alerts/_update/{h['_id']}?refresh=true", {"doc": {"alert": {
            "status": status, "verdict": verdict, "updated_at": now, "updated_by": "lab-attacks", "closed_at": now,
            "closed_by": "lab-attacks", "history": (al.get("history") or [])[-99:] + [note]}}})
        done[verdict] += 1
        print(f"{s.get('rule', {}).get('id')} {ip} {s.get('event_time')}: {verdict}")
    print("tổng:", dict(done))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train")
    t.add_argument("--from", dest="from_", required=True)
    t.add_argument("--to", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--exclude-ips", default="10.10.1.60-69")
    e = sub.add_parser("eval")
    for k in ("train-from", "train-to", "test-from", "test-to", "attacks", "out"):
        e.add_argument("--" + k, required=True)
    e.add_argument("--exclude-ips", default="10.10.1.60-69")
    e.add_argument("--normal-ips", default="10.10.1.40-59")
    e.add_argument("--scores-csv", help="ghi điểm mọi cửa sổ thử ra CSV")
    e.add_argument("--target-fp", type=float, default=0.005, help="như ML_TARGET_FP: phân vị điểm tập giữ lại làm ngưỡng")
    lb = sub.add_parser("label")
    lb.add_argument("--attacks", required=True)
    lb.add_argument("--since", default="now-7d")
    lb.add_argument("--normal-ips", default="10.10.1.40-59")
    a = ap.parse_args()
    {"train": cmd_train, "eval": cmd_eval, "label": cmd_label}[a.cmd](a)


if __name__ == "__main__":
    main()
