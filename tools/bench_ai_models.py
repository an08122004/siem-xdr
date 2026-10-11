"""So sánh model LLM trên cùng pipeline đề xuất rule gap-dataset (KHÔNG lưu đề xuất, không đổi cấu hình).

Chạy trong container ai-worker (cần Elasticsearch + Ollama trong mạng docker):

    docker compose exec ollama ollama pull qwen3:8b
    docker compose cp tools/bench_ai_models.py ai-worker:/tmp/bench.py
    docker compose exec -w /app ai-worker python /tmp/bench.py qwen3:8b 3 sqli sensitive-path \
        atomic-red-team:windows-T1087.002 atomic-red-team:linux-T1552.001

Nhóm web viết tắt theo loại (sqli = csic2010:sqli); nhóm endpoint ghi đủ khóa như trong đề xuất AI
(atomic-red-team:<os>-<kỹ thuật>). Model có chế độ suy nghĩ (qwen3, qwen3.5) chạy với think=false như worker.
Nên dừng ai-worker trước khi đo (`docker compose stop ai-worker`) để chu kỳ tự động không tranh GPU.

Mỗi dòng in ra là 1 JSON: model, nhóm, lần chạy, trạng thái (pending = qua kiểm định), % bắt tập kiểm tra,
báo nhầm, các bước kiểm định trượt (kèm lý do), số lần gọi LLM, thời gian, tốc độ sinh token, điều kiện rule đã
biên dịch và rule Sigma model viết.
"""
import json
import logging
import sys
import time

sys.path.insert(0, ".")
sys.stdout.reconfigure(encoding="utf-8")
logging.basicConfig(level=logging.WARNING)

from siem import settings, store  # noqa: E402
from siem.ai.dataset import ESDataSource  # noqa: E402
from siem.ai.golden import PublicDatasets  # noqa: E402
from siem.ai.llm import OllamaClient  # noqa: E402
from siem.ai.worker import AIWorker  # noqa: E402
from siem.detection.rules import load_rules  # noqa: E402


def main() -> None:
    model, runs, kinds = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
    es = store.connect(templates=False)
    llm = OllamaClient(settings.OLLAMA_URL, model, think=False)
    llm.ensure_model()
    calls = []

    def counting(fn):
        def counted(*a, **kw):
            res = fn(*a, **kw)
            calls.append(res)
            return res
        return counted

    llm.chat_json, llm.chat_text = counting(llm.chat_json), counting(llm.chat_text)
    worker = AIWorker(es, llm, PublicDatasets.load())
    rules = load_rules(settings.RULES_DIR)
    ds = ESDataSource(es)
    gaps = dict(worker.dataset_gaps(rules))
    for kind in kinds:
        key = kind if ":" in kind else f"csic2010:{kind}"
        if key not in gaps:
            print(json.dumps({"model": model, "kind": kind, "status": "error", "error": "không có nhóm này"}), flush=True)
            continue
        for run in range(runs):
            calls.clear()
            t0 = time.time()
            row = {"model": model, "kind": kind, "run": run}
            try:
                p = worker.propose_dataset_rule(key, gaps[key], rules, ds, [])
            except Exception as e:  # noqa: BLE001
                print(json.dumps({**row, "status": "error", "error": str(e)[:200]}, ensure_ascii=False), flush=True)
                continue
            val = p.get("validation") or {}
            m = val.get("metrics", {})
            print(json.dumps({
                **row, "status": p["status"], "test_recall": m.get("test_recall"), "normal_hits": m.get("normal_hits"),
                "failed": [c["name"] for c in val.get("checks", []) if c["blocking"] and not c["ok"]],
                "calls": len(calls), "seconds": round(time.time() - t0),
                "tok_per_s": round(sum(c.output_tokens for c in calls) / max(sum(c.seconds for c in calls), 0.1), 1),
                "condition": (p.get("proposal") or {}).get("condition"),
                "sigma": p.get("sigma") or ("" if p.get("proposal") else (p.get("yaml") or "")[:1500]),
                "why": [c["detail"][:200] for c in val.get("checks", []) if c["blocking"] and not c["ok"]],
                "atoms": (p.get("llm") or {}).get("atoms") or [],
                "attempts": [{"round": a.get("round"), "focus": a.get("focus"), "train_recall": a.get("train_recall"),
                              "kept": len(a.get("kept") or []), "unverified": len(a.get("unverified") or []),
                              "sigmahq_unverified": len(a.get("sigmahq_unverified") or []),
                              "rejected": a.get("rejected") or []} for a in (p.get("llm") or {}).get("attempts") or []],
            }, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
