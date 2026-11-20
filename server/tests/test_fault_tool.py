"""tools/fault_test.py: cách tính các cột Gửi / Có trong ES / Thiếu / Trùng của bảng kiểm thử chịu lỗi."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import fault_test as ft  # noqa: E402


def test_tally_counts_missing_and_duplicates():
    # 5 request gửi, 4 vào ES, một trong số đó bị ghi 3 lần (2 bản thừa)
    assert ft.tally(5, [1, 3, 1, 1]) == {"sent": 5, "present": 4, "missing": 1, "dup": 2}
    assert ft.tally(3, []) == {"sent": 3, "present": 0, "missing": 3, "dup": 0}


def test_tally_alerts_counts_only_soar_processed():
    # FLT-06: 3 alert đã vào ES nhưng SOAR mới xử lý 2 -> thiếu 1
    assert ft.tally(3, [1, 1, 1], processed=2) == {"sent": 3, "present": 2, "missing": 1, "dup": 0}


def test_every_case_in_the_test_plan():
    assert list(ft.CASES) == [f"FLT-0{i}" for i in range(1, 10)]
