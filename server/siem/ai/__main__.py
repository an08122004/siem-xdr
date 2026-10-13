"""Chạy AI worker:

    python -m siem.ai          # vòng lặp (service ai-worker)
    python -m siem.ai --once   # chạy đúng 1 chu kỳ, in tóm tắt rồi thoát (kiểm thử / demo)

Vòng lặp: chờ yêu cầu chạy (analyst bấm trên console -> index ai-jobs) hoặc tới chu kỳ
AI_INTERVAL_MINUTES thì chạy 1 chu kỳ đề xuất. Trạng thái worker ghi vào ai-jobs/_doc/worker.
"""
import argparse
import json
import logging
import sys
import time
import uuid

from .. import settings, store
from . import triage
from .golden import PublicDatasets
from .llm import LLMError, OllamaClient
from .worker import AIWorker, now_iso

log = logging.getLogger("ai")


def set_status(es, **fields) -> None:
    try:
        es.update(index=settings.IDX_AI_JOBS, id="worker", doc={"kind": "status", "updated_at": now_iso(), **fields},
                  doc_as_upsert=True, refresh=True)
    except Exception as e:  # noqa: BLE001
        log.warning("không ghi được trạng thái worker: %s", e)


def claim_job(es) -> dict | None:
    try:
        res = es.search(index=settings.IDX_AI_JOBS, size=1, seq_no_primary_term=True,
                        query={"bool": {"filter": [{"term": {"kind": "job"}}, {"term": {"status": "pending"}}]}},
                        sort=[{"created_at": "asc"}])
    except Exception:  # noqa: BLE001
        return None
    for h in res["hits"]["hits"]:
        try:
            es.update(index=settings.IDX_AI_JOBS, id=h["_id"], doc={"status": "running", "started_at": now_iso()},
                      if_seq_no=h["_seq_no"], if_primary_term=h["_primary_term"], refresh=True)
            return h["_source"] | {"_id": h["_id"]}
        except Exception:  # noqa: BLE001
            continue
    return None


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # console Windows mặc định cp1252
    ap = argparse.ArgumentParser(prog="python -m siem.ai", description="AI worker đề xuất rule / ngoại lệ (chỉ đề xuất)")
    ap.add_argument("--once", action="store_true", help="chạy 1 chu kỳ rồi thoát (không chờ lịch / yêu cầu từ console)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    es = store.connect(templates=False)
    llm = OllamaClient(settings.OLLAMA_URL, settings.AI_MODEL, think=settings.AI_THINK)
    while True:
        try:
            llm.ensure_model()
            break
        except LLMError as e:
            log.warning("Ollama chưa sẵn sàng: %s — thử lại sau 15s", e)
            set_status(es, model=settings.AI_MODEL, model_ready=False, last_error=str(e))
            time.sleep(15)
    if not args.once:
        triage.start(es, llm)            # AI hỗ trợ analyst (tóm tắt, giải thích lệnh...): luồng riêng, không chờ chu kỳ rule
    golden = PublicDatasets.load()
    worker = AIWorker(es, llm, golden)
    set_status(es, model=settings.AI_MODEL, model_ready=True, last_error=None,
               datasets={"attack": len(golden.attack), "normal": len(golden.normal),
                         "unobservable": golden.unobservable, "sigma": len(golden.sigma)})
    if args.once:
        print(json.dumps(worker.run_cycle(requested_by="--once"), ensure_ascii=False, indent=1))
        return
    log.info("AI worker sẵn sàng (model=%s, chu kỳ=%s phút)", settings.AI_MODEL, settings.AI_INTERVAL_MINUTES)
    last_run = 0.0
    while True:
        job = claim_job(es)
        due = settings.AI_INTERVAL_MINUTES > 0 and time.time() - last_run > settings.AI_INTERVAL_MINUTES * 60
        if job or due:
            job_id = job["_id"] if job else f"sched-{uuid.uuid4().hex[:8]}"
            set_status(es, running=True, current_job=job_id)
            try:
                summary = worker.run_cycle(requested_by=(job or {}).get("requested_by") or "lịch tự động")
                status, err = "done", None
            except Exception as e:  # noqa: BLE001
                log.exception("chu kỳ AI lỗi")
                summary, status, err = {}, "error", str(e)
            last_run = time.time()
            if job:
                es.update(index=settings.IDX_AI_JOBS, id=job_id, refresh=True,
                          doc={"status": status, "finished_at": now_iso(), "summary": summary, "error": err})
            set_status(es, running=False, current_job=None, last_run=now_iso(), last_summary=summary, last_error=err)
        time.sleep(10)


if __name__ == "__main__":
    main()
