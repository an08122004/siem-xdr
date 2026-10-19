"""Tải các dataset công khai dùng cho AI worker và đo độ phủ rule (chỉ thư viện chuẩn).

    python tools/fetch_datasets.py          # tải file còn thiếu vào datasets/raw/
    python tools/fetch_datasets.py --force  # tải lại tất cả
    python tools/fetch_datasets.py csic     # chỉ tải dataset có tên file chứa "csic"
    python tools/fetch_datasets.py splunk otrf   # bộ sưu tập lớn (log endpoint ghi thật, vài GB) — chỉ tải khi gọi tên

Sau đó chuyển đổi sang định dạng event của siem-xdr:
    python tools/convert_datasets.py

Dữ liệu bên thứ ba KHÔNG đưa vào repo (datasets/ đã gitignore). Nguồn, giấy phép và
SHA-256 của từng file được ghi vào datasets/SOURCES.md; bộ sưu tập nhiều file ghi SHA-256 từng file vào
datasets/raw/<bộ>/manifest.json (SOURCES.md ghi commit đã ghim + SHA-256 của manifest).
"""
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parent.parent / "datasets"
RAW = ROOT / "raw"
CSIC = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010"


def sigma_release_url() -> tuple[str, str]:
    with urllib.request.urlopen("https://api.github.com/repos/SigmaHQ/sigma/releases/latest", timeout=30) as r:
        rel = json.load(r)
    asset = next(a for a in rel["assets"] if a["name"] == "sigma_all_rules.zip")
    return asset["browser_download_url"], rel["tag_name"]


DATASETS = [
    {
        "name": "Atomic Red Team (index)",
        "file": "atomic-red-team-index.yaml",
        "url": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml",
        "license": "MIT (Red Canary)",
        "home": "https://github.com/redcanaryco/atomic-red-team",
        "use": "Lệnh tấn công theo từng kỹ thuật ATT&CK cho Windows / Linux -> mẫu DƯƠNG cho rule endpoint "
               "(tiến trình, dòng lệnh); dựng thành event Sysmon / process như agent gửi về",
    },
    {
        "name": "EVTX-ATTACK-SAMPLES",
        "file": "evtx-attack-samples.zip",
        "url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip",
        "license": "GPL-3.0",
        "home": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "use": "Windows event log (Security/Sysmon/...) ghi lại khi mô phỏng kỹ thuật tấn công, xếp theo tactic ATT&CK -> mẫu DƯƠNG cho rule Windows",
    },
    {
        "name": "HTTP DATASET CSIC 2010 (anomalous test)",
        "file": "csic2010-anomalousTrafficTest.txt",
        "url": f"{CSIC}/anomalousTrafficTest.txt",
        "license": "Dữ liệu công bố cho nghiên cứu bởi CSIC (Tây Ban Nha); mirror trong repo GPL-3.0 msudol/Web-Application-Attack-Datasets",
        "home": "https://www.tic.itefi.csic.es/dataset/",
        "use": "Request HTTP bất thường (có nhãn) -> mẫu DƯƠNG cho rule Web",
    },
    {
        "name": "HTTP DATASET CSIC 2010 (normal test)",
        "file": "csic2010-normalTrafficTest.txt",
        "url": f"{CSIC}/normalTrafficTest.txt",
        "license": "như trên",
        "home": "https://www.tic.itefi.csic.es/dataset/",
        "use": "Request HTTP bình thường (có nhãn) -> đo báo nhầm của rule Web / rule AI đề xuất",
    },
    {
        "name": "SigmaHQ rules",
        "file": "sigma_all_rules.zip",
        "url": None,  # lấy từ release mới nhất
        "license": "Detection Rule License (DRL) 1.1 — được dùng, phải ghi nguồn tác giả rule",
        "home": "https://github.com/SigmaHQ/sigma",
        "use": "Kho rule phát hiện cộng đồng -> tài liệu tham khảo (RAG) cho AI khi đề xuất rule mới",
    },
]


# ---------------------------------------------------------------- bộ sưu tập nhiều file (repo GitHub, ghim commit)
def _splunk_kind(path: str) -> str | None:
    """Log endpoint trong splunk/attack_data: Sysmon / Security Windows, Sysmon for Linux, auditd."""
    if not path.startswith("datasets/attack_techniques/"):
        return None
    name = path.rsplit("/", 1)[-1]
    if name.endswith((".yml", ".yaml")):
        return "meta"
    if not name.endswith(".log"):
        return None
    if name.endswith(("sysmon_linux.log", "linux-sysmon.log")):
        return "linux-sysmon"
    if "auditd" in path:
        return "linux-auditd"
    if "linux" in name:
        return None
    if name.endswith(("windows-sysmon.log", "sysmon.log", "windows-xml.log")):
        return "win-sysmon"
    if "windows-security" in name or name.endswith("security.log"):
        return "win-security"
    return None


def _otrf_kind(path: str) -> str | None:
    """OTRF: bộ atomic Windows / Linux, chiến dịch compound, metadata YAML (kỹ thuật ATT&CK)."""
    if path.startswith(("datasets/atomic/_metadata/", "datasets/compound/_metadata/")) and path.endswith(".yaml"):
        return "meta"
    data = path.startswith(("datasets/atomic/windows/", "datasets/atomic/linux/", "datasets/compound/"))
    if data and path.endswith((".zip", ".tar.gz")) and "/aws/" not in path:
        return "data"
    return None


COLLECTIONS = {
    "splunk": {
        "name": "Splunk attack_data", "repo": "splunk/attack_data", "dir": "splunk_attack_data", "lfs": True,
        "kind": _splunk_kind, "license": "Apache-2.0", "home": "https://github.com/splunk/attack_data",
        "use": "Log endpoint GHI THẬT khi chạy tấn công (phần lớn là bài thử Atomic Red Team trong Splunk Attack Range): "
               "Sysmon / Security Windows, Sysmon for Linux, auditd, theo kỹ thuật ATT&CK; kèm hoạt động nền của máy",
    },
    "otrf": {
        "name": "OTRF Security-Datasets", "repo": "OTRF/Security-Datasets", "dir": "otrf", "lfs": False,
        "kind": _otrf_kind, "license": "MIT", "home": "https://github.com/OTRF/Security-Datasets",
        "use": "Log Windows ghi thật (Sysmon, Security, PowerShell) khi giả lập tấn công bằng Empire / Covenant / "
               "Metasploit, chiến dịch APT29 / Log4Shell / LSASS; metadata ghi kỹ thuật ATT&CK theo từng bộ",
    },
}
MAX_FILE_MB = 300          # bỏ qua file lớn hơn (ghi vào manifest) để một file khổng lồ không chiếm hết ổ / thời gian


def _get_json(url: str):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "siem-xdr"}), timeout=120) as r:
        return json.load(r)


def _download(url: str, dest: Path, force: bool) -> tuple[str, int, str]:
    """-> (trạng thái, kích thước, lỗi). Ghi qua file .part rồi đổi tên: file đã có luôn là file đầy đủ."""
    if dest.exists() and dest.stat().st_size > 0 and not force:
        return "có sẵn", dest.stat().st_size, ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "siem-xdr"}),
                                        timeout=300) as r:
                size = int(r.headers.get("Content-Length") or 0)
                if size > MAX_FILE_MB * 1_000_000:
                    return "bỏ qua (quá lớn)", size, ""
                with tmp.open("wb") as f:
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
            tmp.replace(dest)
            return "đã tải", dest.stat().st_size, ""
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "lỗi", 0, "404"
            err = str(e)
        except OSError as e:          # gồm cả antivirus chặn ghi file — báo, không tự vượt qua
            err = str(e)
        time.sleep(2 * (attempt + 1))
    tmp.unlink(missing_ok=True)
    return "lỗi", 0, err[:200]


def fetch_collection(key: str, force: bool) -> None:
    c = COLLECTIONS[key]
    base = RAW / c["dir"]
    commit = _get_json(f"https://api.github.com/repos/{c['repo']}/commits/HEAD")["sha"]
    tree = _get_json(f"https://api.github.com/repos/{c['repo']}/git/trees/{commit}?recursive=1")
    if tree.get("truncated"):
        print(f"CẢNH BÁO {c['name']}: danh sách file bị GitHub cắt bớt")
    files = [(t["path"], c["kind"](t["path"])) for t in tree["tree"] if t["type"] == "blob"]
    files = [(p, k) for p, k in files if k]
    print(f"{c['name']} @ {commit[:10]}: {len(files)} file ({', '.join(f'{k} {n}' for k, n in _count(files))})")

    def one(item):
        path, kind = item
        lfs = c["lfs"] and kind != "meta"
        url = (f"https://media.githubusercontent.com/media/{c['repo']}/{commit}/{path}" if lfs
               else f"https://raw.githubusercontent.com/{c['repo']}/{commit}/{path}")
        status, size, err = _download(url, base / path, force)
        return path, kind, status, size, err

    results, t0, done_bytes = [], time.time(), 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for n, r in enumerate(pool.map(one, files), 1):
            results.append(r)
            done_bytes += r[3] if r[2] in ("đã tải", "có sẵn") else 0
            if n % 50 == 0 or n == len(files):
                print(f"  {n}/{len(files)} file, {done_bytes / 1e9:.2f} GB, {time.time() - t0:.0f}s", flush=True)
    by = {}
    for _, _, status, _, _ in results:
        by[status] = by.get(status, 0) + 1
    print("  " + ", ".join(f"{k}: {v}" for k, v in by.items()))
    for path, _, status, size, err in results:
        if status == "lỗi" or status.startswith("bỏ qua"):
            print(f"  {status}: {path} {size / 1e6:.0f} MB {err}")
    ok, skipped = [], [{"path": p, "status": s, "size": z, "error": e} for p, _, s, z, e in results
                        if s not in ("đã tải", "có sẵn")]
    for p, k, status, _, _ in results:
        if status not in ("đã tải", "có sẵn"):
            continue
        try:
            ok.append({"path": p, "kind": k, "size": (base / p).stat().st_size, "sha256": sha256(base / p)})
        except OSError as e:
            # Windows Defender chặn / cách ly file log chứa mẫu mã độc: báo rõ, không tự vượt qua
            skipped.append({"path": p, "status": "không đọc được (antivirus chặn?)", "size": 0, "error": str(e)[:200]})
            print(f"  KHÔNG ĐỌC ĐƯỢC (antivirus chặn?): {p}")
    manifest = {"name": c["name"], "repo": c["repo"], "commit": commit, "license": c["license"],
                "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "files": ok, "skipped": skipped}
    (base / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")


def _count(files):
    out = {}
    for _, k in files:
        out[k] = out.get(k, 0) + 1
    return sorted(out.items())


def collection_rows() -> list[str]:
    rows = []
    for c in COLLECTIONS.values():
        m = RAW / c["dir"] / "manifest.json"
        if not m.exists():
            continue
        man = json.loads(m.read_text(encoding="utf-8"))
        size = sum(f["size"] for f in man["files"])
        rows.append(f"| [{c['name']}]({c['home']}) | `{c['dir']}/` ({len(man['files'])} file, "
                    f"[commit {man['commit'][:10]}](https://github.com/{c['repo']}/tree/{man['commit']})) | "
                    f"{man['downloaded_at'][:10]} | {size / 1e6:.1f} MB | manifest `{sha256(m)[:16]}…` | "
                    f"{c['license']} | {c['use']} |")
    return rows


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    force = "--force" in sys.argv
    rows = []
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    for d in DATASETS:
        dest = RAW / d["file"]
        wanted = not only or any(o.lower() in d["file"].lower() for o in only)
        if not wanted and not dest.exists():
            continue
        # tải riêng 1 dataset (lọc theo tên) vẫn ghi đủ nguồn của mọi file đang có vào SOURCES.md
        url, version = d["url"], "master"
        if url is None:
            url, version = (sigma_release_url() if wanted and (force or not dest.exists())
                            else ("https://github.com/SigmaHQ/sigma/releases", "đã tải trước đó"))
        fresh = wanted and (force or not dest.exists())
        try:
            if fresh:
                print(f"tải  {d['name']}  <- {url}")
                tmp = dest.with_suffix(dest.suffix + ".part")
                with urllib.request.urlopen(url, timeout=300) as r, tmp.open("wb") as f:
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
                tmp.replace(dest)
            else:
                print(f"có sẵn {d['name']}")
            rows.append((d, url, version, dest.stat().st_size, sha256(dest), fresh))
        except OSError as e:
            # Antivirus có thể chặn dataset chứa log/payload tấn công (báo nhầm) -> báo rõ, không tự vượt qua
            print(f"LỖI  {d['name']}: {e}")
            print("     Nếu do antivirus chặn: kiểm tra Protection History, tự quyết định cho phép hay bỏ qua dataset này.")
            rows.append((d, url, version, 0, "KHÔNG ĐỌC ĐƯỢC (antivirus chặn?)", fresh))

    src = ROOT / "SOURCES.md"
    previous = {m.group(1): line for line in (src.read_text(encoding="utf-8").splitlines() if src.exists() else [])
                if (m := re.search(r"\| \[`([^`]+)`\]", line))}
    lines = ["# Nguồn dataset (sinh bởi tools/fetch_datasets.py)", "",
             f"Cập nhật: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "| Dataset | File | Phiên bản | Kích thước | SHA-256 | Giấy phép | Dùng cho |", "|---|---|---|---|---|---|---|"]
    for d, url, version, size, digest, fresh in rows:
        # file không tải lại lần này: giữ dòng cũ (URL / phiên bản lúc tải) nếu SHA-256 vẫn khớp
        old = previous.get(d["file"])
        if not fresh and old and f"`{digest[:16]}…`" in old:
            lines.append(old)
            continue
        lines.append(f"| [{d['name']}]({d['home']}) | [`{d['file']}`]({url}) | {version} | {size / 1e6:.1f} MB | "
                     f"`{digest[:16]}…` | {d['license']} | {d['use']} |")
    for key in COLLECTIONS:
        if key in [o.lower() for o in only]:
            fetch_collection(key, force)
    lines += collection_rows()
    (ROOT / "SOURCES.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"\nđã ghi {ROOT / 'SOURCES.md'}")


if __name__ == "__main__":
    main()
