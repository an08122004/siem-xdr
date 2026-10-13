"""Kiểm tra kho rule trước khi merge (detection-as-code, SOC-OPERATIONS.md mục 4).

    python tools/rule_lint.py                                  # in kết quả, mã thoát 1 nếu có lỗi
    python tools/rule_lint.py --layer build/attack-layer.json  # kèm layer cho MITRE ATT&CK Navigator
    python tools/rule_lint.py --markdown build/rule-lint.md    # báo cáo markdown (CI ghi vào step summary)

Kiểm tra: metadata bắt buộc, biên dịch, ReDoS, id trùng, ca test dương / âm (server/rules/cases), case playbook riêng,
ngoại lệ trỏ đúng rule; độ phủ kỹ thuật ưu tiên theo server/config/threat_profile.yml.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

from siem.detection.lint import attack_layer, lint, markdown  # noqa: E402


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=ROOT / "server" / "rules")
    ap.add_argument("--config", type=Path, default=ROOT / "server" / "config")
    ap.add_argument("--layer", type=Path, help="ghi layer ATT&CK Navigator (JSON)")
    ap.add_argument("--markdown", type=Path, help="ghi báo cáo markdown")
    a = ap.parse_args()
    rep = lint(a.rules, a.config)
    text = markdown(rep)
    print(text)
    for path, content in ((a.markdown, text), (a.layer, json.dumps(attack_layer(rep), ensure_ascii=False, indent=2))):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            print(f"đã ghi {path}")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
