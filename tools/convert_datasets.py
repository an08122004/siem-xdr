"""Chuyển dataset thô (datasets/raw) sang định dạng dùng được trong siem-xdr (datasets/processed):

  csic_normal.jsonl.gz / csic_anomalous.jsonl.gz
      Mỗi request HTTP của CSIC 2010 -> 1 event thô giống hệt event agent gửi lên
      (event_type=apache_access, data.message = dòng Apache combined log) + nhãn.
      Apache access log KHÔNG ghi body -> request POST/PUT có payload trong body được đánh dấu
      observable=false (không thể phát hiện từ access log, báo cáo riêng cho trung thực).
  atomic.jsonl.gz
      Bài thử Atomic Red Team (Windows cmd / PowerShell, Linux sh / bash) -> event tiến trình thô như agent gửi
      (Sysmon EventID 1 / process_creation) + nhãn kỹ thuật ATT&CK. Xem server/siem/ai/atomic.py.
  realdata_attack / realdata_normal / realdata_scenario.jsonl.gz   (nếu đã tải: fetch_datasets.py splunk otrf)
      Log endpoint GHI THẬT (Splunk attack_data, OTRF): event tạo tiến trình Windows / Linux, gắn nhãn tấn công / hoạt
      động nền / chỉ biết theo bộ. Xem server/siem/ai/endpoint_logs.py. Chỉ chạy bước này: convert_datasets.py real
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
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
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


# ---------------------------------------------------------------- log endpoint ghi thật (Splunk attack_data, OTRF)
def _read_jsonl(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


TACTICS: dict[str, list] = {}       # kỹ thuật -> tactic ATT&CK (lấy từ chỉ mục Atomic Red Team)


def _tactics(tech: str) -> list:
    return TACTICS.get(tech) or TACTICS.get(tech.split(".")[0]) or next(
        (v for k, v in TACTICS.items() if k.startswith(tech.split(".")[0] + ".") and v), [])


def _atomic_tests() -> tuple[dict[str, list], dict[str, str]]:
    """kỹ thuật -> [(guid, tên bài thử, token của MỘT dòng lệnh)], kỹ thuật -> tên — từ atomic.jsonl.gz đã dựng."""
    from siem.ai.endpoint_logs import tokens
    tests: dict[str, list] = {}
    names: dict[str, str] = {}
    src = OUT / "atomic.jsonl.gz"
    if not src.exists():
        return tests, names
    seen = set()
    for r in _read_jsonl(src):
        lab, d = r["label"], r["data"]
        cmd = (d.get("fields") or {}).get("CommandLine") or d.get("command_line") or ""
        tok = frozenset(tokens(cmd))
        names.setdefault(lab["technique"], str(lab.get("technique_name") or ""))
        TACTICS.setdefault(lab["technique"], list(lab.get("tactics") or []))
        if tok and (lab["technique"], lab["guid"], tok) not in seen:
            seen.add((lab["technique"], lab["guid"], tok))
            tests.setdefault(lab["technique"], []).append((lab["guid"], lab["test"], set(tok)))
    return tests, names


def _tests_for(tests: dict[str, list], technique: str) -> list:
    return [t for k, v in tests.items() if k == technique or k.startswith(technique + ".") for t in v]


def _otrf_techniques(base: Path) -> dict[str, tuple[list[str], str]]:
    """tên file dữ liệu OTRF -> ([kỹ thuật ATT&CK], tên bộ) từ metadata YAML."""
    out = {}
    for meta in list(base.glob("datasets/atomic/_metadata/*.yaml")) + list(base.glob("datasets/compound/_metadata/*.yaml")):
        try:
            m = yaml.safe_load(meta.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        techs = []
        for a in m.get("attack_mappings") or []:
            t = str(a.get("technique") or "")
            subs = a.get("sub-technique")
            for s in (subs if isinstance(subs, list) else [subs] if subs else [None]):
                techs.append(f"{t}.{str(s).zfill(3)}" if s else t)
        for f in m.get("files") or []:
            out[str(f.get("link") or "").rsplit("/", 1)[-1]] = (sorted(set(t for t in techs if t)), str(m.get("title") or ""))
    return out


def real_endpoint_logs() -> dict[str, dict]:
    from siem.ai.endpoint_logs import dedupe_key, label_file, read_log, to_raw
    tests, names = _atomic_tests()
    attack, normal, scenario = [], [], []
    seen_norm, seen_atk, seen_scn = set(), set(), set()
    norm_techs: dict[tuple, set] = {}
    norm_first: dict[tuple, tuple] = {}
    stats: dict[str, int] = {}
    n = 0

    def add(rows, seen, key, p, label):
        nonlocal n
        if key in seen:
            return
        seen.add(key)
        n += 1
        rows.append(to_raw(p, label, n))

    sp = RAW / "splunk_attack_data"
    if (sp / "manifest.json").exists():
        man = json.loads((sp / "manifest.json").read_text(encoding="utf-8"))
        files = [f for f in man["files"] if f["kind"] != "meta"]
        for k, f in enumerate(files, 1):
            parts = f["path"].split("/")
            tech, scen = parts[2], parts[3]
            kind = "auditd" if f["kind"] == "linux-auditd" else "atomic" if scen == "atomic_red_team" else "scenario"
            try:
                procs = read_log(sp / f["path"])
            except OSError as e:      # antivirus chặn file chứa mẫu mã độc: bỏ, không vượt qua
                print(f"  bỏ (không đọc được): {f['path']} {e}")
                continue
            for p, tag, guid, test in label_file(procs, _tests_for(tests, tech), kind):
                stats[f"splunk {tag}"] = stats.get(f"splunk {tag}", 0) + 1
                lab = {"dataset": "splunk-attack-data", "class": tag, "platform": p.platform, "file": f["path"],
                       "scenario": scen, "source": p.source, "observable": True}
                if tag == "normal":
                    # chỉ nhận là bình thường khi cùng tiến trình xuất hiện ở >= 2 KỸ THUẬT khác nhau: hoạt động nền của máy
                    # Attack Range lặp lại ở mọi lần chạy, còn tấn công chạy ngoài cây Invoke-AtomicTest (mở file .chm, mã độc
                    # giả danh splunkd.exe) chỉ có trong bộ của chính kỹ thuật đó
                    nk = dedupe_key(p)
                    norm_techs.setdefault(nk, set()).add(tech)
                    norm_first.setdefault(nk, (p, {**lab, "dataset": "splunk-background"}))
                    continue
                lab.update(technique=tech, technique_name=names.get(tech) or names.get(tech.split(".")[0], ""),
                           tactics=_tactics(tech), guid=guid or f"splunk:{tech}/{scen}", test=test or scen,
                           program=p.name.lower(), role="real")
                if tag == "attack":
                    add(attack, seen_atk, (tech, guid or scen, *dedupe_key(p)), p, lab)
                else:
                    add(scenario, seen_scn, (f["path"], *dedupe_key(p)), p, lab)
            if k % 100 == 0:
                print(f"  Splunk {k}/{len(files)} file: {len(attack)} tấn công, {len(norm_first)} nền (chưa lọc), "
                      f"{len(scenario)} theo bộ", flush=True)
        for key, (p, lab) in norm_first.items():
            if len(norm_techs[key]) >= 2:
                add(normal, seen_norm, key, p, {**lab, "seen_in_techniques": len(norm_techs[key])})
        stats["nền xuất hiện ở 1 kỹ thuật (bỏ)"] = sum(len(v) < 2 for v in norm_techs.values())
    ot = RAW / "otrf"
    if (ot / "manifest.json").exists():
        man = json.loads((ot / "manifest.json").read_text(encoding="utf-8"))
        techs = _otrf_techniques(ot)
        for f in man["files"]:
            if f["kind"] != "data":
                continue
            name = f["path"].rsplit("/", 1)[-1]
            tl, title = techs.get(name, ([], ""))
            try:
                procs = read_log(ot / f["path"])
            except (OSError, zipfile.BadZipFile, EOFError) as e:
                print(f"  bỏ (không đọc được): {f['path']} {e}")
                continue
            for p in procs:
                stats["otrf scenario"] = stats.get("otrf scenario", 0) + 1
                tech = tl[0] if tl else "unknown"
                lab = {"dataset": "otrf", "class": "scenario", "platform": p.platform, "file": f["path"],
                       "scenario": title or name, "source": p.source, "technique": tech, "techniques": tl,
                       "technique_name": names.get(tech) or names.get(tech.split(".")[0], ""), "tactics": _tactics(tech),
                       "guid": f"otrf:{name}", "test": title or name, "program": p.name.lower(), "role": "real",
                       "observable": True}
                add(scenario, seen_scn, (f["path"], *dedupe_key(p)), p, lab)
    out = {}
    for fname, rows in (("realdata_attack.jsonl.gz", attack), ("realdata_normal.jsonl.gz", normal),
                        ("realdata_scenario.jsonl.gz", scenario)):
        cnt = write_jsonl(fname, rows)
        by = {pl: sum(r["label"]["platform"] == pl for r in rows) for pl in ("windows", "linux")}
        out[fname] = {"events": cnt, **by, "techniques": len({r["label"].get("technique") for r in rows} - {None})}
        print(f"{fname}: {cnt} tiến trình ({by['windows']} Windows, {by['linux']} Linux, "
              f"{out[fname]['techniques']} kỹ thuật)")
    print("  trước khi gộp trùng:", stats)
    return out


def main() -> None:
    steps = {a.lower() for a in sys.argv[1:]}
    if steps == {"real"}:
        # chỉ chạy bước log thật (lâu): giữ nguyên các mục khác trong manifest
        mf = OUT / "manifest.json"
        manifest = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else {}
        manifest.update(real_endpoint_logs())
        mf.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return
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
    atomic = RAW / "atomic-red-team-index.yaml"
    if atomic.exists():
        from siem.ai.atomic import atomic_events          # server/ trong sys.path (xem đầu file)
        rows = list(atomic_events(yaml.safe_load(atomic.read_text(encoding="utf-8"))))
        n = write_jsonl("atomic.jsonl.gz", rows)
        by = {p: sum(r["label"]["platform"] == p for r in rows) for p in ("windows", "linux")}
        manifest["atomic.jsonl.gz"] = {"events": n, **by,
                                       "techniques": len({r["label"]["technique"] for r in rows})}
        print(f"Atomic Red Team: {n} tiến trình ({by['windows']} Windows, {by['linux']} Linux, "
              f"{manifest['atomic.jsonl.gz']['techniques']} kỹ thuật) -> atomic.jsonl.gz")
    else:
        print("Atomic Red Team: chưa có datasets/raw/atomic-red-team-index.yaml (python tools/fetch_datasets.py atomic)")
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
    if (RAW / "splunk_attack_data" / "manifest.json").exists() or (RAW / "otrf" / "manifest.json").exists():
        manifest.update(real_endpoint_logs())
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
