"""Vẽ hình cho báo cáo phần LLM + RAG (sinh rule) từ số đo đã có, ra docs/figures/ai-*.png.

    python tools/report_figures.py        # cần matplotlib (Python của máy, không phải venv server)

Số thô đọc từ datasets/bench_*.jsonl và sigmahq_baseline_*.json; số đã phân tích (ablation 9.9, lý do loại 9.7) đọc
thẳng từ bảng trong AI-README.md để hình luôn khớp tài liệu. Chế độ sáng, cho bản in.
"""
from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA, OUT = ROOT / "datasets", ROOT / "docs" / "figures"

# bảng màu tham chiếu (dataviz): slot 1–3 qua kiểm tra CVD cả cặp kề lẫn mọi cặp ở chế độ sáng
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
PASS = 30  # ngưỡng qua: bắt ≥ 30% tập kiểm tra (AI-README 10.2)
VALIDATION = {"atomic-red-team:windows-T1518.001", "atomic-red-team:linux-T1548.001",
              "splunk-attack-data:windows-T1218.001", "splunk-attack-data:windows-T1218.007"}

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 8.5, "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE, "axes.edgecolor": AXIS, "axes.linewidth": 0.8, "axes.labelcolor": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True, "grid.color": GRID,
    "grid.linewidth": 0.6, "xtick.color": MUTED, "ytick.color": INK2, "xtick.major.size": 0, "ytick.major.size": 0,
    "legend.frameon": False, "savefig.dpi": 200,
})


# ---------------------------------------------------------------- đọc dữ liệu
def jsonl(name: str) -> list[dict]:
    return [json.loads(x) for x in (DATA / name).read_text(encoding="utf-8").splitlines() if x.strip()]


def md_table(heading: str) -> list[list[str]]:
    """Bảng đầu tiên sau dòng tiêu đề `heading` trong AI-README, bỏ dòng tiêu đề và dòng kẻ."""
    lines = (ROOT / "AI-README.md").read_text(encoding="utf-8").splitlines()
    rows: list[list[str]] = []
    for line in lines[next(i for i, x in enumerate(lines) if x.startswith(heading)) + 1:]:
        if line.startswith("|"):
            rows.append([c.strip().replace("*", "") for c in line.strip().strip("|").split("|")])
        elif rows:
            break
    return rows[2:]


def pct(cell: str) -> int:
    """'5/8 (62%)' -> 62; '0/19' -> 0."""
    m = re.search(r"(\d+)%", cell)
    if m:
        return int(m.group(1))
    a, b = re.search(r"(\d+)/(\d+)", cell).groups()
    return round(100 * int(a) / int(b))


def label(kind: str) -> str:
    web = {"sqli": "Web: SQL Injection", "sensitive-path": "Web: tài nguyên nhạy cảm"}
    if kind in web:
        return web[kind]
    src, _, rest = kind.partition(":")
    os_, _, tech = rest.partition("-")
    tag = "dựng lại" if src == "atomic-red-team" else "log thật"
    return f"{'Win' if os_ == 'windows' else 'Linux'} {tech} ({tag})" + (" *" if kind in VALIDATION else "")


def kind_of(name: str, kinds: set[str]) -> str:
    """Tên nhóm trong bảng AI-README -> mã nhóm của dataset."""
    if "SQL" in name:
        return "sqli"
    if "nhạy cảm" in name:
        return "sensitive-path"
    os_ = "windows" if "Windows" in name else "linux"
    tech = re.search(r"T\d{4}(?:\.\d{3})?", name).group()
    src = "atomic-red-team" if "dựng lại" in name else "splunk-attack-data" if "log thật" in name else ""
    hits = [k for k in kinds if k.endswith(f":{os_}-{tech}") and k.startswith(src)]
    assert len(hits) == 1, (name, hits)
    return hits[0]


def kinds() -> set[str]:
    return {r["kind"] for r in jsonl("bench_v9_2026-10-09.jsonl")}


def ablation() -> dict[str, tuple[int, int, int]]:
    """AI-README 9.9: nhóm -> (chỉ vế model, + lượt kiến thức, + vế SigmaHQ), % bắt tập kiểm tra, TB 3 lần."""
    ks = kinds()
    return {kind_of(r[0], ks): (pct(r[-3]), pct(r[-2]), pct(r[-1])) for r in md_table("### 9.9")}


def sigmahq_baseline() -> dict[str, int]:
    """AI-README 9.5: nhóm -> % bắt của các rule SigmaHQ cùng kỹ thuật không báo nhầm, cộng lại. Lấy bảng chứ không
    lấy datasets/sigmahq_baseline_2026-10-07.json: file đó chặt hơn (đánh dấu báo nhầm nhiều rule hơn, 5 thay vì 6/14
    nhóm đạt 30%), lệch số mà tài liệu trích dẫn."""
    ks = kinds()
    return {kind_of(r[0], ks): pct(r[2]) for r in md_table("### 9.5")}


# ---------------------------------------------------------------- khung hình
def frame(fig, title: str, sub: str, above: float = 0.0) -> None:
    """Tiêu đề + phụ đề đặt theo inch (không đè nhau ở mọi chiều cao); `above` = inch dành cho legend / tiêu đề panel
    nằm trên vùng vẽ."""
    h = fig.get_figheight()
    fig.text(0.01, 1 - 0.04 / h, title, ha="left", va="top", fontsize=11, fontweight="bold", color=INK)
    fig.text(0.01, 1 - 0.30 / h, sub, ha="left", va="top", fontsize=8, color=INK2, linespacing=1.5)
    fig.subplots_adjust(top=1 - (0.50 + 0.17 * (sub.count("\n") + 1) + above) / h)


def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    print("đã ghi", (OUT / name).relative_to(ROOT))


def threshold_line(ax, y_text: float, z: float = 1) -> None:
    ax.axvline(PASS, color=INK2, linewidth=0.9, zorder=z)
    ax.text(PASS + 1, y_text, f"ngưỡng qua {PASS}%", color=INK2, fontsize=7.5, va="bottom")


# ---------------------------------------------------------------- hình
def fig_models() -> None:
    names = {"qwen2.5-coder:7b": "qwen2.5-coder:7b", "qwen3:8b": "qwen3:8b", "qwen3.5:9b": "qwen3.5:9b (đang dùng)",
             "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF": "Foundation-Sec-1.1-8B"}
    runs = [("Đợt 1: web + endpoint dựng lại", jsonl("bench_models_2026-10-06.jsonl"), S1),
            ("Đợt 2: log ghi thật", jsonl("bench_models_real_2026-10-07.jsonl"), S2)]
    metrics = [("Số nhóm qua kiểm định (trên 8)", lambda rr: sum(r["status"] == "pending" for r in rr), 8),
               ("Bắt tập kiểm tra, trung bình (%)", lambda rr: round(100 * statistics.mean(r["test_recall"] or 0 for r in rr)), 100),
               ("Thời gian chạy 8 nhóm (phút)", lambda rr: round(sum(r["seconds"] for r in rr) / 60), None)]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.9), sharey=True)
    h = 0.34
    for ax, (title, f, top) in zip(axes, metrics):
        for j, (_, rows, color) in enumerate(runs):
            for i, m in enumerate(names):
                rr = [r for r in rows if r["model"] == m]
                if not rr:
                    continue
                v = f(rr)
                y = i + (h / 2 + 0.02) * (-1 if j == 0 else 1)          # trục y đảo: đợt 1 nằm trên
                ax.barh(y, v, height=h, color=color, zorder=2)
                ax.text(v, y, f" {v}", va="center", fontsize=7.5, color=INK2)
        ax.set_title(title, loc="left", fontsize=8.5, color=INK, pad=6)
        ax.grid(axis="x")
        ax.set_xlim(0, (top or max(ax.get_xlim()[1], 1)) * 1.15)
        ax.spines["left"].set_visible(False)
    axes[0].set_yticks(range(len(names)), list(names.values()))
    axes[0].set_xticks(range(0, 9, 2))
    axes[0].invert_yaxis()
    fig.legend(handles=[Line2D([], [], color=c, lw=6, label=n) for n, _, c in runs], loc="lower left",
               bbox_to_anchor=(0.01, -0.06), ncol=2, fontsize=8)
    frame(fig, "So sánh 4 model LLM chạy cục bộ trong pipeline sinh rule",
          "Mỗi nhóm chạy 1 lần, GPU Quadro RTX 4000 8 GB; qwen2.5-coder:7b không chạy đợt 2\n"
          "Nguồn: datasets/bench_models_*.jsonl (AI-README 9.4)", above=0.25)
    fig.subplots_adjust(bottom=0.12, wspace=0.12)
    save(fig, "ai-1-so-sanh-model.png")


def fig_ablation() -> None:
    data = sorted(ablation().items(), key=lambda kv: (kv[1][2], kv[1][0]))
    fig, ax = plt.subplots(figsize=(7.2, 5.6))
    parts = [("Vế do model viết", S1), ("+ lượt kiến thức (hỏi cách làm khác)", S2),
             ("+ vế SigmaHQ truy hồi (RAG)", S3)]
    for i, (_, (m, k, s)) in enumerate(data):
        left = 0
        for v, (_, color) in zip((m, k - m, s - k), parts):
            if v > 0:
                ax.barh(i, v, left=left, height=0.62, color=color, edgecolor=SURFACE, linewidth=1.5, zorder=2)
            left += v
        ax.text(s + 1, i, f"{s}%", va="center", fontsize=7.5, color=INK2, zorder=4,
                bbox={"boxstyle": "square,pad=0.15", "fc": SURFACE, "ec": "none"})
    i3 = next(i for i, (k, _) in enumerate(data) if k.endswith("T1003.003"))
    m, _, s = data[i3][1]
    ax.annotate(f"model một mình {m}% → cả rule {s}%", xy=(s + 6, i3), xytext=(s + 9, i3 - 2.2), fontsize=7.5,
                color=INK, arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.8})
    ax.set_yticks(range(len(data)), [label(k) for k, _ in data])
    ax.set_xlim(0, 112)
    ax.set_xlabel("Tỉ lệ bắt tập kiểm tra (%), trung bình 3 lần")
    ax.grid(axis="x")
    ax.spines["left"].set_visible(False)
    threshold_line(ax, len(data) - 0.4, z=3)
    ax.legend(handles=[Line2D([], [], color=c, lw=6, label=n) for n, c in parts], loc="lower left",
              bbox_to_anchor=(0, 1.0), ncol=3, fontsize=8)
    fig.text(0.01, -0.01, "* nhóm kiểm chứng, không dùng khi thiết kế pipeline. Chạy với LLM giả (chỉ còn vế SigmaHQ): "
             "3/20 nhóm qua.", fontsize=7.5, color=INK2)
    frame(fig, "Đóng góp của từng thành phần vào tỉ lệ bắt", "qwen3.5:9b, 20 nhóm, 3 lần mỗi nhóm\n"
          "Nguồn: AI-README 9.9, datasets/bench_v9_2026-10-09.jsonl", above=0.30)
    fig.subplots_adjust(left=0.30)
    save(fig, "ai-2-dong-gop-rag.png")


def fig_complement() -> None:
    model = {k: v[0] for k, v in ablation().items()}
    pts = [(x, model[k], k) for k, x in sigmahq_baseline().items()]
    # nhãn chọn lọc: hai nhóm cả hai đạt và hai ví dụ trái chiều; số đếm từng góc + bảng 9.5 mang phần còn lại
    named = {"atomic-red-team:windows-T1087.002", "splunk-attack-data:windows-T1548.002",
             "splunk-attack-data:windows-T1003.003", "atomic-red-team:linux-T1552.001"}
    fig, ax = plt.subplots(figsize=(6.4, 5.2))
    ax.scatter([x for x, _, _ in pts], [y for _, y, _ in pts], s=42, color=S1, edgecolor=SURFACE, linewidth=1.5,
               zorder=3)
    ax.axvline(PASS, color=INK2, linewidth=0.9, zorder=1)
    ax.axhline(PASS, color=INK2, linewidth=0.9, zorder=1)
    corner = {(1, 1): "cả hai đạt", (1, 0): "chỉ SigmaHQ đạt", (0, 1): "chỉ model đạt", (0, 0): "cả hai trượt"}
    for (cx, cy), text in corner.items():
        n = sum((x >= PASS) == cx and (y >= PASS) == cy for x, y, _ in pts)
        ax.text(104 if cx else -3, 115 if cy else -10, f"{text}: {n} nhóm", ha="right" if cx else "left",
                va="top" if cy else "bottom", fontsize=8, color=MUTED, fontweight="bold")
    for x, y, k in pts:
        if k not in named:
            continue
        crowded = any(k2 in named and 0 < x2 - x < 15 and abs(y2 - y) < 6 for x2, y2, k2 in pts)
        ax.annotate(label(k).split(" ", 1)[1], (x, y), xytext=(0, 8) if crowded else (6, -3),
                    textcoords="offset points", ha="center" if crowded else "left", fontsize=7.5, color=INK2)
    ax.set_xlim(-5, 106)
    ax.set_ylim(-11, 116)
    ax.set_xlabel("Các rule SigmaHQ cùng kỹ thuật, cộng lại (% bắt tập kiểm tra)")
    ax.set_ylabel("Chỉ vế do model viết, TB 3 lần (%)")
    ax.grid(True)
    frame(fig, "Kho tri thức SigmaHQ và model bổ sung cho nhau",
          f"Mỗi điểm là một nhóm kỹ thuật endpoint ({len(pts)} nhóm), ngưỡng qua 30%\n"
          "Nguồn: AI-README 9.5 (trục ngang), 9.9 (trục dọc)")
    save(fig, "ai-3-sigmahq-va-model.png")


def fig_rejections() -> None:
    rows = [(r[0], int(r[1].split()[0])) for r in md_table("### 9.7")]
    total = sum(n for _, n in rows)
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    for i, (name, n) in enumerate(rows):
        ax.barh(i, n, height=0.55, color=S1 if i == 0 else AXIS, zorder=2)
        ax.text(n + 2, i, f"{n} · {round(100 * n / total)}%", va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(rows)), [n for n, _ in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, max(n for _, n in rows) * 1.2)
    ax.set_xlabel("Số vế ứng viên bị loại")
    ax.grid(axis="x")
    ax.spines["left"].set_visible(False)
    frame(fig, f"Vì sao vế ứng viên bị loại ({total} vế)",
          "Pipeline Sigma 8/10/2026, qwen3.5:9b và Foundation-Sec\n"
          "Nguồn: AI-README 9.7, datasets/bench_sigma_2026-10-08.jsonl")
    fig.subplots_adjust(left=0.27)
    save(fig, "ai-4-ly-do-loai.png")


def fig_stability() -> None:
    by: dict[str, list[tuple[float, bool]]] = {}
    for r in jsonl("bench_v9_2026-10-09.jsonl"):
        by.setdefault(r["kind"], []).append((100 * (r["test_recall"] or 0), r["status"] == "pending"))
    data = sorted(by.items(), key=lambda kv: statistics.mean(v for v, _ in kv[1]))
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    for i, (_, runs) in enumerate(data):
        vals = [v for v, _ in runs]
        ax.plot([min(vals), max(vals)], [i, i], color=AXIS, linewidth=2, solid_capstyle="round", zorder=1)
        ax.plot([statistics.mean(vals)] * 2, [i - 0.28, i + 0.28], color=INK, linewidth=1.2, zorder=4)
        for v, ok in sorted(runs, key=lambda x: x[1]):      # lần bị loại vẽ trước, lần qua đè lên
            ax.scatter(v, i, s=40, zorder=3, color=S1 if ok else SURFACE, edgecolor=S1 if ok else MUTED,
                       linewidth=1.5 if not ok else 1.0)
    ax.set_yticks(range(len(data)), [label(k) for k, _ in data])
    ax.set_xlim(-3, 108)
    ax.set_xlabel("Tỉ lệ bắt tập kiểm tra (%) của từng lần chạy")
    ax.grid(axis="x")
    ax.spines["left"].set_visible(False)
    threshold_line(ax, len(data) - 0.4)
    ax.legend(handles=[Line2D([], [], marker="o", ls="", color=S1, markersize=6, label="lần chạy qua kiểm định"),
                       Line2D([], [], marker="o", ls="", markerfacecolor=SURFACE, markeredgecolor=MUTED, markersize=6,
                              label="lần chạy bị loại"),
                       Line2D([], [], marker="|", ls="", color=INK, markersize=9, label="trung bình 3 lần")],
              loc="lower left", bbox_to_anchor=(0, 1.0), ncol=3, fontsize=8)
    fig.text(0.01, -0.01, "* nhóm kiểm chứng. Một lần chạy có thể bắt ≥ 30% mà vẫn bị loại (báo nhầm, luật chặn "
             "regex yếu).", fontsize=7.5, color=INK2)
    frame(fig, "Kết quả dao động giữa 3 lần chạy cùng một nhóm",
          "qwen3.5:9b, pipeline v9\nNguồn: datasets/bench_v9_2026-10-09.jsonl (AI-README 9.9)", above=0.30)
    fig.subplots_adjust(left=0.30)
    save(fig, "ai-5-on-dinh.png")


if __name__ == "__main__":
    for f in (fig_models, fig_ablation, fig_complement, fig_rejections, fig_stability):
        f()
