"""So sánh model LLM trên cùng pipeline đề xuất rule gap-dataset (KHÔNG lưu đề xuất, không đổi cấu hình).

Chạy trong container ai-worker (cần Elasticsearch + Ollama trong mạng docker):

    docker compose exec ollama ollama pull qwen3:8b
    docker compose cp tools/bench_ai_models.py ai-worker:/tmp/bench.py
    docker compose exec -w /app ai-worker python /tmp/bench.py qwen3:8b 3 sqli sensitive-path backup-file crlf ssi encoding-evasion

Mỗi dòng in ra là 1 JSON: model, loại, lần chạy, trạng thái (pending = qua kiểm định), % bắt tập kiểm tra,
báo nhầm, các bước kiểm định trượt, số lần gọi LLM, thời gian, điều kiện rule.
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


class Client(OllamaClient):
    """Tắt chế độ suy nghĩ của model có thinking (qwen3...) để so sánh cùng điều kiện với model thường."""

    def _post(self, path, body, timeout=None):
        if path == "/api/chat" and self.model.startswith("qwen3"):
            body = {**body, "think": False}
        return super()._post(path, body, timeout)


def main() -> None:
    model, runs, kinds = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
    es = store.connect(templates=False)
    llm = Client(settings.OLLAMA_URL, model)
    calls = []
    orig = llm.chat_json

    def counted(*a, **kw):
        calls.append(1)
        return orig(*a, **kw)

    llm.chat_json = counted
    worker = AIWorker(es, llm, PublicDatasets.load())
    rules = load_rules(settings.RULES_DIR)
    ds = ESDataSource(es)
    gaps = dict(worker.dataset_gaps(rules))
    for kind in kinds:
        for run in range(runs):
            calls.clear()
            t0 = time.time()
            row = {"model": model, "kind": kind, "run": run}
            try:
                p = worker.propose_dataset_rule(f"csic2010:{kind}", gaps[f"csic2010:{kind}"], rules, ds, [])
            except Exception as e:  # noqa: BLE001
                print(json.dumps({**row, "status": "error", "error": str(e)[:200]}, ensure_ascii=False), flush=True)
                continue
            val = p.get("validation") or {}
            m = val.get("metrics", {})
            print(json.dumps({
                **row, "status": p["status"], "test_recall": m.get("test_recall"), "normal_hits": m.get("normal_hits"),
                "failed": [c["name"] for c in val.get("checks", []) if c["blocking"] and not c["ok"]],
                "calls": len(calls), "seconds": round(time.time() - t0),
                "condition": (p.get("proposal") or {}).get("condition"),
            }, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
