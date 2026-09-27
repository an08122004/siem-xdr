"""Chuyển dataset thô (datasets/raw) sang định dạng dùng được trong siem-xdr (datasets/processed):

  csic_normal.jsonl.gz / csic_anomalous.jsonl.gz
      Mỗi request HTTP của CSIC 2010 -> 1 event thô giống hệt event agent gửi lên
      (event_type=apache_access, data.message = dòng Apache combined log) + nhãn.
      Apache access log KHÔNG ghi body -> request POST/PUT có payload trong body được đánh dấu
      observable=false (không thể phát hiện từ access log, báo cáo riêng cho trung thực).
  evtx.jsonl.gz   (nếu có datasets/raw/evtx-attack-samples.zip và cài python-evtx)
      Mỗi bản ghi .evtx -> event thô windows_event như agent Windows gửi + nhãn tactic ATT&CK.
  sigma_rules.jsonl.gz
      Rút gọn rule SigmaHQ (tiêu đề, mô tả, logsource, tag ATT&CK, detection) làm tài liệu RAG.

Chạy (dùng venv của server vì cần PyYAML):
    server/.venv/Scripts/python tools/convert_datasets.py
"""
from __future__ import annotations

import gzip
import io
import json
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import yaml

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parent.parent / "datasets"
RAW, OUT = ROOT / "raw", ROOT / "processed"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
REQ_LINE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE) (\S+) (HTTP/1\.[01])$")


def write_jsonl(name: str, rows) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(OUT / name, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


# ---------------------------------------------------------------- CSIC 2010
def parse_csic(path: Path):
    lines = path.read_text(encoding="latin-1").splitlines()
    i = 0
    while i < len(lines):
        m = REQ_LINE.match(lines[i].strip())
        if not m:
            i += 1
            continue
        method, url, proto = m.groups()
        headers: dict[str, str] = {}
        i += 1
        while i < len(lines) and lines[i].strip():
            k, _, v = lines[i].partition(":")
            headers[k.strip().lower()] = v.strip()
            i += 1
        body = ""
        if "content-length" in headers:
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i < len(lines) and not REQ_LINE.match(lines[i].strip()):
                body = lines[i].strip()
                i += 1
        yield method, url, proto, headers, body


def csic_events(path: Path, label: str, ip_base: int):
    for n, (method, url, proto, headers, body) in enumerate(parse_csic(path)):
        path_q = re.sub(r"^https?://[^/]+", "", url) or "/"
        ts = T0 + timedelta(seconds=n)
        # IP tổng hợp, mỗi request 1 IP (dải 10.200.0.0/16 cho normal, 10.201.0.0/16 cho anomalous)
        ip = f"10.{ip_base}.{(n // 250) % 256}.{n % 250 + 1}"
        ua = headers.get("user-agent", "-").replace('"', "'")
        line = (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path_q} {proto}" '
                f'200 {len(body) or 512} "-" "{ua}"')
        yield {
            "timestamp": ts.isoformat(), "agent_id": "dataset-csic2010", "hostname": "csic-shop", "os": "linux",
            "source": "file", "event_type": "apache_access", "data": {"message": line},
            "label": {"dataset": "csic2010", "class": label, "method": method,
                      # payload nằm trong body (POST/PUT) -> access log không thấy
                      "observable": label == "normal" or not body},
        }


# ---------------------------------------------------------------- EVTX-ATTACK-SAMPLES
def evtx_events(zip_path: Path):
    try:
        from Evtx.Evtx import Evtx  # pip install python-evtx
    except ImportError:
        print("  bỏ qua EVTX: chưa cài python-evtx (pip install python-evtx)")
        return
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with zipfile.ZipFile(zip_path) as z:
        for name in sorted(n for n in z.namelist() if n.lower().endswith(".evtx")):
            parts = name.split("/")
            tactic = parts[1] if len(parts) > 2 else "unknown"
            with Evtx(io.BytesIO(z.read(name))) as log:  # type: ignore[arg-type]
                for rec in log.records():
                    try:
                        root = ET.fromstring(rec.xml())
                    except ET.ParseError:
                        continue
                    sysn = root.find("e:System", ns)
                    fields = {}
                    for i, d in enumerate(root.findall("e:EventData/e:Data", ns)):
                        fields[d.get("Name") or f"param{i + 1}"] = (d.text or "").strip()
                    tc = sysn.find("e:TimeCreated", ns).get("SystemTime") if sysn.find("e:TimeCreated", ns) is not None else None
                    yield {
                        "timestamp": (tc or T0.isoformat()).replace(" ", "T"),
                        "agent_id": "dataset-evtx", "hostname": sysn.findtext("e:Computer", "", ns), "os": "windows",
                        "source": "eventlog", "event_type": "windows_event",
                        "data": {"event_id": int(sysn.findtext("e:EventID", "0", ns) or 0),
                                 "channel": sysn.findtext("e:Channel", "", ns),
                                 "provider": (sysn.find("e:Provider", ns).get("Name") if sysn.find("e:Provider", ns) is not None else ""),
                                 "computer": sysn.findtext("e:Computer", "", ns),
                                 "record_id": int(sysn.findtext("e:EventRecordID", "0", ns) or 0), "fields": fields},
                        "label": {"dataset": "evtx-attack-samples", "class": "attack", "tactic": tactic,
                                  "file": parts[-1], "observable": True},
                    }


# ---------------------------------------------------------------- Sigma
def sigma_rules(zip_path: Path):
    with zipfile.ZipFile(zip_path) as z:
        for name in sorted(n for n in z.namelist() if n.endswith(".yml")):
            try:
                r = yaml.safe_load(z.read(name))
            except yaml.YAMLError:
                continue
            if not isinstance(r, dict) or "detection" not in r:
                continue
            det = yaml.safe_dump(r["detection"], allow_unicode=True, sort_keys=False, width=200)
            yield {
                "id": r.get("id"), "title": r.get("title"), "description": (r.get("description") or "")[:500],
                "status": r.get("status"), "level": r.get("level"), "logsource": r.get("logsource") or {},
                "tags": [t for t in (r.get("tags") or []) if str(t).startswith("attack.")],
                "detection": det[:1500], "author": r.get("author"), "path": name,
            }


def main() -> None:
    manifest: dict[str, dict] = {}
    for fname, label, base, out in [("csic2010-normalTrafficTest.txt", "normal", 200, "csic_normal.jsonl.gz"),
                                    ("csic2010-anomalousTrafficTest.txt", "anomalous", 201, "csic_anomalous.jsonl.gz")]:
        src = RAW / fname
        if src.exists():
            rows = list(csic_events(src, label, base))
            n = write_jsonl(out, rows)
            obs = sum(r["label"]["observable"] for r in rows)
            manifest[out] = {"events": n, "observable": obs}
            print(f"CSIC {label:9s}: {n} request ({obs} quan sát được trong access log) -> {out}")
    evtx_zip = RAW / "evtx-attack-samples.zip"
    try:
        if evtx_zip.exists():
            n = write_jsonl("evtx.jsonl.gz", evtx_events(evtx_zip))
            if n:
                manifest["evtx.jsonl.gz"] = {"events": n}
                print(f"EVTX: {n} bản ghi -> evtx.jsonl.gz")
        else:
            print("EVTX: không có datasets/raw/evtx-attack-samples.zip — bỏ qua")
    except OSError as e:
        print(f"EVTX: không đọc được ({e}) — có thể bị antivirus chặn, bỏ qua")
    sig = RAW / "sigma_all_rules.zip"
    if sig.exists():
        n = write_jsonl("sigma_rules.jsonl.gz", sigma_rules(sig))
        manifest["sigma_rules.jsonl.gz"] = {"rules": n}
        print(f"Sigma: {n} rule -> sigma_rules.jsonl.gz")
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
