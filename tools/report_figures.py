"""Vẽ hình cho báo cáo từ số đo đã có, ra docs/figures/: ai-*.png (LLM + RAG sinh rule), ml-*.png (ML bất thường).

    python tools/report_figures.py        # cần matplotlib (Python của máy, không phải venv server)

LLM: số thô đọc từ datasets/bench_*.jsonl; số đã phân tích (9.5, 9.7, 9.9) đọc thẳng từ bảng trong AI-README.md để hình
luôn khớp tài liệu. ML: datasets/ml_scores_2026-11-17.csv do `ml_eval.py eval --scores-csv` ghi (lần 2 của
docs/ml-eval-2026-11-17.md: học 15/11 08:20 -> 16/11 14:04:06, thử -> 17/11 16:30 UTC) và nhãn
datasets/ml_attacks_2026-11-17.jsonl. Chế độ sáng, cho bản in.
"""
from __future__ import annotations

import csv
import json
import math
import re
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch, Rectangle  # noqa: E402

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


def vn(x: float, d: int) -> str:
    """Số trong câu tiếng Việt: dấu phẩy thập phân."""
    return f"{x:.{d}f}".replace(".", ",")


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


# ---------------------------------------------------------------- ML bất thường
SCEN = {"scan_dirs": "dò thư mục", "portal_bruteforce": "dò mật khẩu portal", "password_spray": "rải mật khẩu",
        "ssh_bruteforce": "dò mật khẩu SSH", "slow_scan": "dò chậm", "scraper": "cào trang", "exfil": "tuồn dữ liệu"}


def ml_rows() -> tuple[list[dict], dict[str, str]]:
    """Cửa sổ thử (bỏ nhãn `other`: IP ngoài cả hai dải) và IP -> kịch bản (mỗi kịch bản một IP riêng)."""
    with (DATA / "ml_scores_2026-11-17.csv").open(encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["label"] != "other"]
    for r in rows:
        r["score"], r["threshold"] = float(r["score"]), float(r["threshold"])
    return rows, {a["ip"]: a["scenario"] for a in jsonl("ml_attacks_2026-11-17.jsonl")}


ML_SUB = "Học 15/11 08:20 → 16/11 14:04, thử 26,4 giờ tới 17/11 16:30 (UTC)\nNguồn: datasets/ml_scores_2026-11-17.csv " \
         "(ml_eval --scores-csv), docs/ml-eval-2026-11-17.md lần 2"


def fig_ml_hist() -> None:
    rows, scen = ml_rows()
    models = [("web", "Model web"), ("auth", "Model auth")]
    fig, axes = plt.subplots(2, 2, figsize=(7.2, 4.6), sharex="col",
                             gridspec_kw={"height_ratios": [3, 2], "hspace": 0.1, "wspace": 0.45})
    for c, (name, title) in enumerate(models):
        rr = [r for r in rows if r["model"] == name]
        th = rr[0]["threshold"]
        normal = [r["score"] for r in rr if r["label"] == "normal"]
        attack = [(scen[r["ip"]], r["score"]) for r in rr if r["label"] == "attack"]
        top, bot = axes[0][c], axes[1][c]
        lo, hi = min(normal + [s for _, s in attack]), max(normal)
        w = 0.02
        top.hist(normal, bins=[math.floor(lo / w) * w + i * w for i in range(int((hi - lo) / w) + 3)], color=S1,
                 edgecolor=SURFACE, linewidth=1.0, zorder=2)
        top.set_title(f"{title}: {len(normal)} cửa sổ thường, {sum(s < th for s in normal)} bị gắn cờ",
                      loc="left", fontsize=8.5, color=INK, pad=6)
        top.set_ylabel("Số cửa sổ thường")
        top.grid(axis="y")
        names = [n for n in SCEN if any(a == n for a, _ in attack)]
        for n, s in attack:
            bot.scatter(s, names.index(n), s=40, zorder=3, color=S2 if s < th else SURFACE, edgecolor=S2, linewidth=1.5)
        bot.set_yticks(range(len(names)),
                       [f"{SCEN[n]} ({sum(a == n for a, _ in attack)})" for n in names], fontsize=7.5)
        bot.set_ylim(len(names) - 0.4, -0.6)
        bot.grid(axis="x")
        bot.set_xlabel("Điểm Isolation Forest (thấp = bất thường)")
        for ax in (top, bot):
            ax.axvline(th, color=INK2, linewidth=0.9, zorder=4)
            ax.spines["left"].set_visible(False)
        top.text(th, top.get_ylim()[1], f" ngưỡng {vn(th, 3)}\n ← bị gắn cờ", va="top", ha="left", fontsize=7.5,
                 color=INK2)
    fig.legend(handles=[Line2D([], [], color=S1, lw=6, label="cửa sổ người dùng thường"),
                        Line2D([], [], marker="o", ls="", color=S2, markersize=6, label="cửa sổ tấn công bị gắn cờ"),
                        Line2D([], [], marker="o", ls="", markerfacecolor=SURFACE, markeredgecolor=S2, markersize=6,
                               label="cửa sổ tấn công lọt")],
               loc="upper left", bbox_to_anchor=(0.01, 1 - 0.92 / 4.6), ncol=3, fontsize=8)
    frame(fig, "Phân bố điểm bất thường: người dùng thường và tấn công", ML_SUB, above=0.72)
    fig.text(0.01, -0.02, "Số trong ngoặc: số cửa sổ của kịch bản. Ngưỡng = phân vị 0,5% điểm của 20% cửa sổ học mới nhất.",
             fontsize=7.5, color=INK2)
    save(fig, "ml-1-histogram-diem.png")


def roc(pos: list[float], neg: list[float]) -> tuple[list[tuple[float, float]], float]:
    """Đường ROC (FPR, TPR) và AUC; điểm lớn hơn = bất thường hơn, điểm bằng nhau đi chéo (hình thang)."""
    pts = [(0.0, 0.0)] + [(sum(n >= t for n in neg) / len(neg), sum(p >= t for p in pos) / len(pos))
                          for t in sorted(set(pos) | set(neg), reverse=True)]
    return pts, sum((x2 - x1) * (y1 + y2) / 2 for (x1, y1), (x2, y2) in zip(pts, pts[1:]))


assert roc([2.0], [1.0])[1] == 1.0 and roc([1.0], [1.0])[1] == 0.5 and roc([1.0], [2.0])[1] == 0.0


def pr_curve(pos: list[float], neg: list[float]) -> tuple[list[tuple[float, float]], float]:
    """Đường (recall, precision) theo ngưỡng giảm dần, dừng khi recall đạt 100% (như sklearn), và average precision
    = Σ (R_n − R_{n−1}) · P_n."""
    pts = []
    for t in sorted(set(pos) | set(neg), reverse=True):
        tp, fp = sum(p >= t for p in pos), sum(n >= t for n in neg)
        pts.append((tp / len(pos), tp / (tp + fp)))
        if tp == len(pos):
            break
    return pts, sum((r2 - r1) * p2 for (r1, _), (r2, p2) in zip([(0.0, 1.0)] + pts, pts))


assert pr_curve([2.0], [1.0])[1] == 1.0 and pr_curve([1.0], [2.0])[1] == 0.5


def fig_ml_roc() -> None:
    rows, _ = ml_rows()
    # gộp 2 model theo khoảng cách tới ngưỡng riêng của từng model: > 0 nghĩa là bị gắn cờ ở cả hai model
    pos = [r["threshold"] - r["score"] for r in rows if r["label"] == "attack"]
    neg = [r["threshold"] - r["score"] for r in rows if r["label"] == "normal"]
    pts, auc = roc(pos, neg)
    op = (sum(n > 0 for n in neg) / len(neg), sum(p > 0 for p in pos) / len(pos))
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.6), gridspec_kw={"wspace": 0.3})
    for ax, xmax, title in ((axes[0], 1.0, "Toàn dải"), (axes[1], 0.05, "Phóng to: tỉ lệ báo nhầm ≤ 5%")):
        ax.plot([0, xmax], [0, xmax], color=AXIS, linewidth=0.9, zorder=1)
        ax.plot([x for x, _ in pts], [y for _, y in pts], color=S1, linewidth=2, solid_joinstyle="round", zorder=2)
        ax.scatter(*op, s=48, color=INK, edgecolor=SURFACE, linewidth=1.5, zorder=3)
        ax.set_xlim(-xmax * 0.02, xmax)
        ax.set_ylim(-0.02, 1.04)
        ax.set_title(title, loc="left", fontsize=8.5, color=INK, pad=6)
        ax.set_xlabel("Tỉ lệ báo nhầm (FPR)")
        ax.grid(True)
        ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0 if xmax == 1 else 1))
        ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    axes[0].set_ylabel("Tỉ lệ bắt cửa sổ tấn công (TPR)")
    axes[1].annotate(f"ngưỡng đang dùng: bắt {sum(p > 0 for p in pos)}/{len(pos)} cửa sổ tấn công,\n"
                     f"báo nhầm {sum(n > 0 for n in neg)}/{len(neg)} ({vn(100 * op[0], 2)}%)", op, xytext=(14, -30),
                     textcoords="offset points", fontsize=7.5, color=INK,
                     arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.8})
    full = min(x for x, y in pts if y == 1)
    frame(fig, f"Đường ROC của ML bất thường (AUC = {vn(auc, 2)})",
          f"{len(pos)} cửa sổ tấn công (7 kịch bản), {len(neg)} cửa sổ người dùng thường; gộp model web và auth theo "
          f"khoảng cách tới ngưỡng riêng\n" + ML_SUB.split("\n", 1)[1], above=0.25)
    fig.text(0.01, -0.03, "Đường chéo xám: đoán ngẫu nhiên. Phần lọt (cào trang, tuồn dữ liệu) lẫn vào đuôi phân bố của "
             f"người dùng thường: muốn bắt đủ 100% phải chấp nhận báo nhầm {vn(100 * full, 1)}%.", fontsize=7.5,
             color=INK2)
    save(fig, "ml-2-roc.png")


def fig_ml_pr() -> None:
    rows, _ = ml_rows()
    pos = [r["threshold"] - r["score"] for r in rows if r["label"] == "attack"]
    neg = [r["threshold"] - r["score"] for r in rows if r["label"] == "normal"]
    pts, ap = pr_curve(pos, neg)
    base = len(pos) / (len(pos) + len(neg))
    tp, fp = sum(p > 0 for p in pos), sum(n > 0 for n in neg)
    op = (tp / len(pos), tp / (tp + fp))
    full = pts[-1][1]                                       # precision tại ngưỡng đầu tiên bắt đủ mọi cửa sổ tấn công
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    ax.axhline(base, color=AXIS, linewidth=0.9, zorder=1)
    ax.text(0.01, base + 0.02, f"đoán ngẫu nhiên = tỉ lệ cửa sổ tấn công trong tập thử ({vn(100 * base, 1)}%)",
            fontsize=7.5, color=INK2, va="bottom")
    ax.step([0.0] + [r for r, _ in pts], [pts[0][1]] + [p for _, p in pts], where="pre", color=S1, linewidth=2,
            zorder=2)
    ax.scatter(*op, s=48, color=INK, edgecolor=SURFACE, linewidth=1.5, zorder=3)
    ax.annotate(f"ngưỡng đang dùng: {tp} đúng / {tp + fp} cảnh báo\nprecision {vn(100 * op[1], 0)}%, "
                f"recall {vn(100 * op[0], 0)}%", op, xytext=(0.30, 0.72), fontsize=7.5, color=INK,
                arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.8})
    ax.scatter(1.0, full, s=48, color=SURFACE, edgecolor=INK, linewidth=1.5, zorder=3)
    ax.annotate(f"bắt đủ {len(pos)}/{len(pos)} cửa sổ: precision chỉ còn {vn(100 * full, 0)}%", (1.0, full),
                xytext=(0.30, 0.13), fontsize=7.5, color=INK, arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.8})
    ax.set_xlim(-0.02, 1.04)
    ax.set_ylim(-0.02, 1.06)
    ax.set_xlabel("Recall: tỉ lệ cửa sổ tấn công bị gắn cờ")
    ax.set_ylabel("Precision: tỉ lệ cảnh báo là tấn công thật")
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.grid(True)
    frame(fig, f"Precision–Recall của ML bất thường (AP = {vn(ap, 2)})",
          f"{len(pos)} cửa sổ tấn công (7 kịch bản), {len(neg)} cửa sổ người dùng thường; gộp model web và auth theo "
          f"khoảng cách tới ngưỡng riêng\n" + ML_SUB.split("\n", 1)[1])
    fig.text(0.01, -0.04, "Precision phụ thuộc tỉ lệ tấn công trong tập thử: 7 kịch bản chạy dồn trong 70 phút nên tấn công "
             f"chiếm {vn(100 * base, 1)}% cửa sổ.\nThực tế tấn công hiếm hơn, cùng ngưỡng thì precision thấp hơn; tỉ lệ "
             "báo nhầm ở hình ROC không phụ thuộc điều này.", fontsize=7.5, color=INK2, va="top", linespacing=1.4)
    save(fig, "ml-3-precision-recall.png")


def fig_ml_target() -> None:
    """Đánh đổi theo ML_TARGET_FP. Forest giữ nguyên ở mọi mức (random_state=0), chỉ ngưỡng dịch: ngưỡng từng mức do
    `ml_eval eval --target-fp` tính (datasets/ml_target_fp_2026-11-17.csv), điểm lấy từ file điểm chung."""
    rows, scen = ml_rows()
    th: dict[str, dict[str, float]] = {}
    with (DATA / "ml_target_fp_2026-11-17.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            th.setdefault(r["target_fp"], {})[r["model"]] = float(r["threshold"])
    cur, levels, names = "0.005", list(th), list(SCEN)
    assert all(th[cur][r["model"]] == r["threshold"] for r in rows)     # hai file dữ liệu cùng một lần học
    normal = [r for r in rows if r["label"] == "normal"]

    def flag(r: dict, t: str) -> bool:
        return r["score"] < th[t][r["model"]]

    caught = {t: [any(flag(r, t) for r in rows if r["label"] == "attack" and scen[r["ip"]] == n) for n in names]
              for t in levels}
    fp = [sum(flag(r, t) for r in normal) for t in levels]
    fig, (top, bot) = plt.subplots(2, 1, figsize=(7.2, 5.4), sharex=True,
                                   gridspec_kw={"height_ratios": [3, 2], "hspace": 0.15})
    ci = levels.index(cur)
    for ax in (top, bot):
        ax.axvspan(ci - 0.42, ci + 0.42, color="#f0efec", zorder=0)
        ax.spines["left"].set_visible(False)
    for j, t in enumerate(levels):
        for i, ok in enumerate(caught[t]):
            top.scatter(j, i, s=60, zorder=3, color=S2 if ok else SURFACE, edgecolor=S2 if ok else MUTED, linewidth=1.5)
        top.text(j, -0.85, f"{sum(caught[t])}/7", ha="center", va="bottom", fontsize=8, color=INK, fontweight="bold")
    top.set_yticks(range(len(names)), [SCEN[n] for n in names])
    top.set_ylim(len(names) - 0.5, -1.05)
    top.spines["bottom"].set_visible(False)
    top.tick_params(axis="x", length=0)
    top.legend(handles=[Line2D([], [], marker="o", ls="", color=S2, markersize=7, label="bắt được (≥ 1 cửa sổ bị gắn cờ)"),
                        Line2D([], [], marker="o", ls="", markerfacecolor=SURFACE, markeredgecolor=MUTED, markersize=7,
                               label="bỏ sót")], loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=8)
    bot.plot(range(len(levels)), [100 * n / len(normal) for n in fp], color=S1, linewidth=2, marker="o", markersize=6,
             markeredgecolor=SURFACE, markeredgewidth=1.5, zorder=3)
    for j in (ci, len(levels) - 1):
        bot.annotate(f"{fp[j]}/{len(normal)} ({vn(100 * fp[j] / len(normal), 2)}%)", (j, 100 * fp[j] / len(normal)),
                     xytext=(0, 8), textcoords="offset points", ha="center", fontsize=7.5, color=INK2)
    bot.set_ylim(0, 100 * max(fp) / len(normal) * 1.3)
    bot.set_ylabel("Báo nhầm trên\ncửa sổ thường (%)")
    bot.grid(axis="y")
    bot.text(ci, bot.get_ylim()[1], "đang dùng", ha="center", va="top", fontsize=7.5, color=INK2)
    bot.set_xticks(range(len(levels)), [vn(100 * float(t), 1).rstrip("0").rstrip(",") + "%" for t in levels])
    bot.set_xlabel("ML_TARGET_FP (phân vị điểm của tập giữ lại dùng làm ngưỡng)")
    frame(fig, "Đánh đổi theo ML_TARGET_FP: kịch bản bắt được và báo nhầm",
          "Cùng một model, chỉ dịch ngưỡng; 7 kịch bản tấn công, 568 cửa sổ người dùng thường\n"
          "Nguồn: datasets/ml_scores_2026-11-17.csv, ml_target_fp_2026-11-17.csv (ml_eval --target-fp)", above=0.30)
    fig.subplots_adjust(left=0.2)
    save(fig, "ml-4-danh-doi-target-fp.png")


# ---------------------------------------------------------------- sơ đồ pipeline AI (AI-README mục 2)
NEUTRAL = "#f0efec"
PALE_BLUE, PALE_AQUA = "#dfebf9", "#ddf3eb"


def _box(ax, x: float, y: float, w: float, h: float, title: str, body: str, fc: str = NEUTRAL, ec: str | None = None,
         tc: str = INK) -> None:
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.1", fc=fc, ec=ec or fc, lw=1.3))
    ax.text(x + 0.12, y + h - 0.13, title, ha="left", va="top", fontsize=7.0, fontweight="bold", color=tc)
    ax.text(x + 0.12, y + h - 0.42, body, ha="left", va="top", fontsize=6.0, color=INK2 if tc == INK else tc,
            linespacing=1.35)


def _arrow(ax, p: tuple[float, float], q: tuple[float, float], rad: float = 0.0, label: str = "",
           at: tuple[float, float] | None = None) -> None:
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=9, lw=0.9, color=INK2,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1, zorder=1))
    if label:
        ax.text(*(at or ((p[0] + q[0]) / 2, (p[1] + q[1]) / 2)), label, ha="center", va="center", fontsize=6.4,
                color=INK2, linespacing=1.3)


def fig_pipeline() -> None:
    # khung 12 x 6,2 đơn vị lấp đúng vùng vẽ 7,2 x 3,72 inch (tỉ lệ 1:1 để góc bo tròn không méo)
    fig, ax = plt.subplots(figsize=(7.2, 4.56))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6.2)
    ax.set_aspect("equal")
    ax.axis("off")
    w, g, h, top, bot = 2.12, 0.3, 1.35, 3.7, 1.25
    xs = [0.1 + i * (w + g) for i in range(5)]
    _box(ax, xs[0], top, w, h, "Ứng viên", "mẫu tấn công Wazuh\nchưa bắt (khoảng trống);\nalert báo nhầm")
    _box(ax, xs[1], top, w, h, "Chuẩn bị", "gom nhóm theo kỹ thuật,\ntách train / kiểm tra,\ntập bình thường")
    _box(ax, xs[2], top, w, h, "Truy hồi (RAG)", "SigmaHQ: 3.302 rule;\nxếp theo từ khóa, cùng\nkỹ thuật ATT&CK, cùng\nnguồn log", PALE_AQUA, S3)
    _box(ax, xs[3], top, w, h, "LLM cục bộ", "qwen3.5:9b (Ollama)\n→ rule Sigma YAML", PALE_BLUE, S1)
    _box(ax, xs[4], top, w, h, "Biên dịch + ghép vế", "Sigma → cây điều kiện;\nđo từng vế trên train\nvà tập bình thường")
    _box(ax, xs[4], bot, w, h, "Kiểm định độc lập", "tập kiểm tra model\nchưa thấy, báo nhầm,\nreplay 7 ngày")
    _box(ax, xs[3], bot, w, h, "Cổng Wazuh", "dịch sang XML, bơm log\nthô vào sandbox; đo bắt,\nbáo nhầm, che rule khác")
    _box(ax, xs[2], bot, w, h, "Người duyệt", "trên console; kiểm tra\nlại với dữ liệu mới nhất")
    _box(ax, xs[0], bot, 2 * w + g, h, "Triển khai", "ghi rules-dynamic/ai.xml, reload Wazuh,\nchạy bóng (SOAR bỏ qua); "
         "đạt tiêu chí\nbóng thì bật chính thức")
    _box(ax, xs[3], 0.05, 2 * w + g, 0.8, "Loại", "lưu lý do để xem lại; sửa bộ dịch thì thử lại ngay (R81)", tc=MUTED)
    y = top + h / 2
    for i in range(4):
        _arrow(ax, (xs[i] + w, y), (xs[i + 1], y))
    _arrow(ax, (xs[4] + 0.75, top + h), (xs[3] + w - 0.6, top + h), rad=0.5,
           label="vế bị loại kèm lý do, biến thể còn sót (nhiều lượt)", at=(xs[4] - 0.02, top + h + 0.78))
    _arrow(ax, (xs[2] + w / 2, top), (xs[4] + 0.5, top), rad=0.18)
    ax.text((xs[2] + xs[4]) / 2 + 0.75, top - 0.62, "vế ứng viên SigmaHQ", ha="center", va="center", fontsize=6.2,
            color=INK2)
    xc = xs[4] + w / 2
    _arrow(ax, (xc, top), (xc, bot + h))
    yb = bot + h / 2
    for i in (4, 3, 2):
        _arrow(ax, (xs[i], yb), (xs[i - 1] + w if i > 2 else xs[1] + w, yb))
    for x in (xs[3] + w / 2, xc):
        _arrow(ax, (x, bot), (x, 0.85))
    frame(fig, "Pipeline AI sinh rule phát hiện: LLM kết hợp RAG",
          "Tự động từ ứng viên tới cổng Wazuh, con người duyệt trước khi triển khai; xanh dương = model, xanh lục = "
          "SigmaHQ truy hồi\nNguồn: AI-README mục 2, server/siem/ai/ (worker, golden, sigma, validate, wazuh_gate, "
          "deploy)")
    fig.subplots_adjust(bottom=0.0, left=0.0, right=1.0)
    save(fig, "ai-0-pipeline.png")


# ---------------------------------------------------------------- ATT&CK
TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
           "collection", "command-and-control", "exfiltration", "impact"]
RAMP = [(1, "#86b6ef"), (2, "#3987e5"), (5, "#1c5cab"), (20, "#0d366b")]   # số rule ra alert từ ... -> bậc màu
ATTACK_SUB = "Nguồn: catalog siem-rules của stack thật ngày 19/11/2026 (datasets/attack_rules_2026-11-19.csv), " \
             "danh mục ATT&CK đi kèm Wazuh 4.14.8 (mitre.db)"


def attack_data() -> tuple[dict[str, list[str]], dict[tuple[str, str], dict[str, set[str]]]]:
    """Kỹ thuật cha theo tactic, và (nguồn, trạng thái) -> kỹ thuật -> rule. Trạng thái `alert` theo định nghĩa phủ của
    KPI (rules_catalog.attack_coverage, R49): qua cầu nối, mode active, không bóng, đang bật; `bong` = chạy bóng. Kỹ thuật
    con tính cho kỹ thuật cha; mã không có trong danh mục (rule ghi '(không có)') bị bỏ."""
    tactics: dict[str, list[str]] = {t: [] for t in TACTICS}
    with (DATA / "attack_enterprise_wazuh-4.14.8.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if "." not in r["technique"]:
                tactics[r["tactic"]].append(r["technique"])
    known = {t for ts in tactics.values() for t in ts}
    cov: dict[tuple[str, str], dict[str, set[str]]] = {}
    with (DATA / "attack_rules_2026-11-19.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            src = "sigmahq" if r["file"].endswith("0966-sigmahq.xml") else "du_an" if r["file"].startswith("etc/") \
                else "goc"
            bong = r["shadow"] == "True" or r["mode"] == "shadow"
            alert = not bong and r["bridged"] == "True" and r["mode"] == "active" and r["status"].lower() == "enabled"
            if alert or bong:
                for t in {x.split(".")[0] for x in r["techniques"].split()} & known:
                    cov.setdefault((src, "bong" if bong else "alert"), {}).setdefault(t, set()).add(r["rule_id"])
    return tactics, cov


def tactic_name(t: str) -> str:
    return " ".join(w if w == "and" else w.capitalize() for w in t.split("-"))


HEAD = {"reconnaissance": "Recon-\nnaissance", "exfiltration": "Exfil-\ntration", "command-and-control": "Command\nand Control"}


def tactic_head(t: str) -> str:
    """Tên tactic cho cột hẹp: hai dòng, không ngắt giữa từ (trừ hai từ quá dài, ngắt có gạch nối)."""
    return HEAD.get(t) or tactic_name(t).replace(" ", "\n", 1)


def fig_attack_matrix() -> None:
    tactics, cov = attack_data()
    alert: dict[str, set[str]] = {}
    for (_, st), d in cov.items():
        if st == "alert":
            for t, ids in d.items():
                alert.setdefault(t, set()).update(ids)
    bong = {t for (_, st), d in cov.items() if st == "bong" for t in d} - alert.keys()
    total = {t for ts in tactics.values() for t in ts}
    rows = max(len(v) for v in tactics.values())
    fig, ax = plt.subplots(figsize=(7.4, 8.6))
    for c, tac in enumerate(TACTICS):
        techs = sorted(tactics[tac], key=lambda t: (-len(alert.get(t, ())), t not in bong, t))
        ax.text(c + 0.5, -1.0, tactic_head(tac), ha="center", va="bottom", fontsize=6.0, fontweight="bold", color=INK,
                linespacing=1.15)
        ax.text(c + 0.5, -0.25, f"{sum(t in alert for t in techs)}/{len(techs)}", ha="center", va="bottom",
                fontsize=6.8, color=INK2)
        for i, t in enumerate(techs):
            k = len(alert.get(t, ()))
            if k:
                fc = next(col for lo, col in reversed(RAMP) if k >= lo)
                tc, ec = (INK if fc == RAMP[0][1] else "#ffffff"), fc
            elif t in bong:
                fc, tc, ec = SURFACE, INK, S2
            else:
                fc, tc, ec = NEUTRAL, MUTED, NEUTRAL
            ax.add_patch(Rectangle((c + 0.05, i + 0.06), 0.9, 0.88, fc=fc, ec=ec, lw=1.0 if ec == S2 else 0))
            ax.text(c + 0.5, i + 0.52, t, ha="center", va="center", fontsize=5.2, color=tc)
    ax.set_xlim(0, len(TACTICS))
    ax.set_ylim(rows + 0.1, -2.3)
    ax.axis("off")
    labels = ["1 rule", "2–4 rule", "5–19 rule", "≥ 20 rule"]
    handles = [Patch(fc=col, ec=col, label=lab) for (_, col), lab in zip(RAMP, labels)]
    handles += [Patch(fc=SURFACE, ec=S2, label="chỉ có rule chạy bóng"), Patch(fc=NEUTRAL, ec=NEUTRAL, label="chưa có")]
    fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.01, 1 - 0.84 / 8.6), ncol=6, fontsize=7.5,
               handlelength=1.4, columnspacing=1.2)
    n = sum(t in alert for t in total)
    frame(fig, f"Độ phủ MITRE ATT&CK của rule ra alert: {n}/{len(total)} kỹ thuật ({round(100 * n / len(total))}%)",
          "Mỗi ô là một kỹ thuật cha, màu theo số rule Wazuh ra alert thật (không tính rule chạy bóng); kỹ thuật con "
          "tính cho kỹ thuật cha\n" + ATTACK_SUB, above=0.38)
    fig.subplots_adjust(left=0.01, right=0.99, bottom=0.01)
    save(fig, "attack-1-ma-tran.png")


def fig_attack_sources() -> None:
    tactics, cov = attack_data()
    cols = [("Wazuh gốc\n(ra alert)", [("goc", "alert")]), ("Rule dự án\n(ra alert)", [("du_an", "alert")]),
            ("SigmaHQ\n(chạy bóng)", [("sigmahq", "bong")]), ("Tổng\n(ra alert)", [("goc", "alert"), ("du_an", "alert")])]
    ramp = matplotlib.colors.LinearSegmentedColormap.from_list(
        "seq", ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"])
    fig, ax = plt.subplots(figsize=(6.6, 5.6))
    for r, tac in enumerate(TACTICS):
        techs = set(tactics[tac])
        for c, (_, keys) in enumerate(cols):
            got = set().union(*(cov.get(k, {}).keys() for k in keys)) & techs
            frac = len(got) / len(techs)
            fc = ramp(frac) if got else NEUTRAL
            ax.add_patch(Rectangle((c + 0.04, r + 0.06), 0.92, 0.88, fc=fc, ec=fc, lw=0))
            text = f"{len(got)}" + (f" · {round(100 * frac)}%" if c == len(cols) - 1 else "")
            ax.text(c + 0.5, r + 0.52, text, ha="center", va="center", fontsize=7.5,
                    color="#ffffff" if got and frac >= 0.45 else (INK if got else MUTED))
    ax.set_xlim(0, len(cols))
    ax.set_ylim(len(TACTICS), -0.05)
    ax.set_yticks([r + 0.5 for r in range(len(TACTICS))],
                  [f"{tactic_name(t)} ({len(tactics[t])})" for t in TACTICS], fontsize=7.5)
    ax.set_xticks([c + 0.5 for c in range(len(cols))], [n for n, _ in cols], fontsize=7.5)
    ax.tick_params(axis="x", labelcolor=INK)
    ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    sm = matplotlib.cm.ScalarMappable(cmap=ramp, norm=matplotlib.colors.Normalize(0, 100))
    cb = fig.colorbar(sm, ax=ax, orientation="horizontal", fraction=0.035, pad=0.03, aspect=40)
    cb.set_label("Tỉ lệ kỹ thuật của tactic được phủ (%)", fontsize=7.5, color=INK2)
    cb.outline.set_visible(False)
    cb.ax.tick_params(labelsize=7, colors=MUTED, length=0)
    frame(fig, "Kỹ thuật ATT&CK được phủ, theo tactic và nguồn rule",
          "Số kỹ thuật cha có ít nhất một rule (trong ngoặc: tổng kỹ thuật của tactic); chưa có rule AI nào được "
          "duyệt\n" + ATTACK_SUB, above=0.45)
    fig.text(0.01, -0.02, "Tổng = hợp của Wazuh gốc và rule dự án, không cộng SigmaHQ vì đang chạy bóng (chưa ra alert).",
             fontsize=7.5, color=INK2)
    save(fig, "attack-2-theo-nguon.png")


if __name__ == "__main__":
    for f in (fig_models, fig_ablation, fig_complement, fig_rejections, fig_stability, fig_ml_hist, fig_ml_roc,
              fig_ml_pr, fig_ml_target, fig_pipeline, fig_attack_matrix, fig_attack_sources):
        f()
