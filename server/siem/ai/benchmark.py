"""Đo độ phủ rule hiện tại trên dataset công khai.

    python -m siem.ai.benchmark                 # in tóm tắt
    python -m siem.ai.benchmark --write FILE.md # ghi báo cáo markdown
"""
import argparse
import logging
import sys
from pathlib import Path

from .. import settings
from ..detection.rules import load_rules
from .golden import PublicDatasets, report_markdown


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", type=Path, default=None)
    ap.add_argument("--rules", type=Path, default=settings.RULES_DIR)
    ap.add_argument("--max-normal", type=int, default=36000)
    ap.add_argument("--write", type=Path, default=None)
    a = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)
    rules = load_rules(a.rules)
    ds = PublicDatasets.load(a.datasets, max_normal=a.max_normal)
    rep = ds.evaluate(rules)
    md = report_markdown(rep, rules)
    if a.write:
        a.write.write_text(md, encoding="utf-8", newline="\n")
        print(f"đã ghi {a.write}")
    print(md[: md.find("## Theo rule")] if "## Theo rule" in md else md)


if __name__ == "__main__":
    main()
