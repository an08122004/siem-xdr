"""Tải các dataset công khai dùng cho AI worker và đo độ phủ rule (chỉ thư viện chuẩn).

    python tools/fetch_datasets.py          # tải file còn thiếu vào datasets/raw/
    python tools/fetch_datasets.py --force  # tải lại tất cả
    python tools/fetch_datasets.py csic     # chỉ tải dataset có tên file chứa "csic"

Sau đó chuyển đổi sang định dạng event của siem-xdr:
    python tools/convert_datasets.py

Dữ liệu bên thứ ba KHÔNG đưa vào repo (datasets/ đã gitignore). Nguồn, giấy phép và
SHA-256 của từng file được ghi vào datasets/SOURCES.md.
"""
import hashlib
import json
import sys
import urllib.request
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
        if only and not any(o.lower() in d["file"].lower() for o in only):
            continue
        url, version = d["url"], "master"
        if url is None:
            url, version = sigma_release_url()
        dest = RAW / d["file"]
        try:
            if force or not dest.exists():
                print(f"tải  {d['name']}  <- {url}")
                tmp = dest.with_suffix(dest.suffix + ".part")
                with urllib.request.urlopen(url, timeout=300) as r, tmp.open("wb") as f:
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
                tmp.replace(dest)
            else:
                print(f"có sẵn {d['name']}")
            rows.append((d, url, version, dest.stat().st_size, sha256(dest)))
        except OSError as e:
            # Antivirus có thể chặn dataset chứa log/payload tấn công (báo nhầm) -> báo rõ, không tự vượt qua
            print(f"LỖI  {d['name']}: {e}")
            print("     Nếu do antivirus chặn: kiểm tra Protection History, tự quyết định cho phép hay bỏ qua dataset này.")
            rows.append((d, url, version, 0, "KHÔNG ĐỌC ĐƯỢC (antivirus chặn?)"))

    lines = ["# Nguồn dataset (sinh bởi tools/fetch_datasets.py)", "",
             f"Cập nhật: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "| Dataset | File | Phiên bản | Kích thước | SHA-256 | Giấy phép | Dùng cho |", "|---|---|---|---|---|---|---|"]
    for d, url, version, size, digest in rows:
        lines.append(f"| [{d['name']}]({d['home']}) | [`{d['file']}`]({url}) | {version} | {size / 1e6:.1f} MB | "
                     f"`{digest[:16]}…` | {d['license']} | {d['use']} |")
    (ROOT / "SOURCES.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"\nđã ghi {ROOT / 'SOURCES.md'}")


if __name__ == "__main__":
    main()
