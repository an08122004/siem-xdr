"""Rule TẦN SUẤT cho khoảng trống do ML phát hiện (nguồn `gap-ml` của worker): đếm số lần một rule Wazuh CÓ SẴN khớp
từ cùng IP nguồn trong `timeframe` giây, như rule gốc 31151 (`if_matched_sid` + `same_source_ip`).

Đo trên wazuh-sandbox 4.14.8 (19/11/2026): rule nền level 0 không được đếm; `frequency=N` kích hoạt đúng ở event thứ N rồi
bộ đếm về 0; rule nền MỚI làm con của rule gốc thì cướp event của rule gốc (31151 mất đếm). Vì vậy không sinh rule nền:
rule tần suất đếm thẳng rule đã khớp các event của sự cố (31101 lỗi 4xx web, 101000 bộ đếm đăng nhập thất bại...).
Ngưỡng do dữ liệu quyết định (người dùng thường), không để LLM đoán.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

MIN_COUNT = 3        # ngưỡng tối thiểu: 1–2 lần lặp là chuyện thường (gõ sai mật khẩu, link hỏng)


def by_ip(events: Iterable[tuple[str, float]]) -> dict[str, list[float]]:
    """(ip, thời điểm) -> ip: danh sách thời điểm đã sắp xếp."""
    out: dict[str, list[float]] = defaultdict(list)
    for ip, t in events:
        if ip:
            out[ip].append(t)
    return {ip: sorted(ts) for ip, ts in out.items()}


def max_in_span(times: list[float], span: float) -> int:
    """Số event nhiều nhất nằm trong một khoảng dài `span` giây bất kỳ (cửa sổ TRƯỢT như timeframe của Wazuh)."""
    return busiest(times, span)[0]


def busiest(times: list[float], span: float) -> tuple[int, float]:
    """(số event nhiều nhất trong một khoảng `span`, thời điểm bắt đầu khoảng đó)."""
    best, start, lo = 0, times[0] if times else 0.0, 0
    for hi, t in enumerate(times):
        while t - times[lo] > span:
            lo += 1
        if hi - lo + 1 > best:
            best, start = hi - lo + 1, times[lo]
    return best, start


def fires(times: list[float], count: int, span: float) -> list[float]:
    """Thời điểm rule tần suất kích hoạt: đủ `count` event trong `span` giây thì kích hoạt và bộ đếm về 0 (đo sandbox).
    shortcut: không mô phỏng event bị rule anh em (vd 31151) giành mất khỏi bộ đếm, nên có thể đếm dư vài event; đủ
    chính xác để đặt ngưỡng / ước lượng báo nhầm, cổng sandbox mới là phép đo thật."""
    out, recent = [], []
    for t in times:
        recent = [x for x in recent if t - x <= span] + [t]
        if len(recent) >= count:
            out.append(t)
            recent = []
    return out


def threshold(normal: dict[str, list[float]], span: float) -> int:
    """Ngưỡng = số lần nhiều nhất một IP bình thường đạt trong một khoảng `span`, cộng 1 (không thấp hơn MIN_COUNT)."""
    return max([max_in_span(ts, span) for ts in normal.values()] + [MIN_COUNT - 1]) + 1
