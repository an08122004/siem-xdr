"""Giám sát sức khỏe nguồn log và chính nền tảng SOC (SOC-OPERATIONS.md mục 5). Chạy trong SOAR mỗi phút, sinh alert
HLT-* bằng SOAR (ghi thẳng Elasticsearch, không qua analyzer / Kafka) để vẫn báo được khi đường ống đang hỏng.

  HLT-001  agent Wazuh mất kết nối quá AGENT_DOWN_MINUTES phút (theo keepalive Wazuh), mức theo tài sản
  HLT-002  nguồn log im lặng: không event nào trong SOURCE_SILENT_MINUTES phút dù trung bình 7 ngày phải có
           >= SOURCE_MIN_EXPECTED event trong khoảng đó
  HLT-003  lưu lượng 1 giờ qua lệch quá VOLUME_DEVIATION (mặc định 50%) so với trung bình 7 ngày (nguồn >= 100 event/giờ)
  HLT-004  mất đồng bộ trạng thái agent với Wazuh manager (SOAR không gọi được Wazuh API)
  HLT-005  Kafka nghẽn: consumer analyzer / SOAR tụt sau quá KAFKA_LAG_MAX_MESSAGES message liên tục KAFKA_LAG_MINUTES phút
  HLT-006  Elasticsearch: cluster đỏ, hoặc đĩa quá ES_DISK_MAX_PCT%
  HLT-007  sao lưu: chưa có chính sách snapshot, lần chạy gần nhất lỗi, hoặc bản thành công gần nhất cũ hơn
           SNAPSHOT_MAX_AGE_HOURS giờ (security/setup.sh tạo chính sách SLM daily-snapshots)

Mỗi sự cố chỉ một alert đang mở (khóa: mã + nguồn); hết sự cố thì ghi "đã hồi phục" vào lịch sử alert để analyst đóng.
Trạng thái từng nguồn ghi vào index siem-sources (Grafana "SOC KPI": sức khỏe nguồn log)."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .. import priority as prio
from .. import settings, store
from ..detection.rules import SEVERITY_SCORE

log = logging.getLogger("soar.health")

IDX_SOURCES = "siem-sources"
ACTIVE = ["open", "acknowledged", "in_progress"]
SKIP_SOURCES = {"soc-console"}            # nhật ký đăng nhập console: thưa, im lặng là bình thường
CHECKS = {
    "HLT-001": ("Agent mất kết nối", ["T1562.001"], "Defense Evasion"),
    "HLT-002": ("Nguồn log im lặng", ["T1562.001"], "Defense Evasion"),
    "HLT-003": ("Lưu lượng log lệch bất thường", [], None),
    "HLT-004": ("Mất đồng bộ trạng thái agent với Wazuh manager", [], None),
    "HLT-005": ("Đường ống Kafka bị nghẽn", [], None),
    "HLT-006": ("Elasticsearch lỗi hoặc sắp đầy đĩa", [], None),
    "HLT-007": ("Sao lưu Elasticsearch không chạy", [], None),
}
SLM_POLICY = "daily-snapshots"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _parse(ts: Any) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class HealthMonitor:
    def __init__(self, es, emit: Callable[[dict[str, Any]], Any], assets=None, kafka_lag: Callable | None = None,
                 clock=time.time):
        self.es, self.emit, self.assets, self.kafka_lag, self.clock = es, emit, assets, kafka_lag, clock
        self.open: dict[tuple[str, str], str] = {}        # (mã, nguồn) -> id alert đang mở
        self.lag_since: dict[str, float] = {}               # consumer group -> lúc bắt đầu tụt quá ngưỡng
        self.last_volume: dict[str, float] = {}             # nguồn -> lần báo HLT-003 gần nhất
        self._loaded = False

    # ------------------------------------------------------------------ alert
    def load_open(self) -> None:
        rows = store.search(self.es, settings.IDX_ALERTS, {"bool": {"filter": [
            {"term": {"alert.source": "health"}}, {"terms": {"alert.status": ACTIVE}}]}}, size=1000)
        for a in rows:
            self.open[(str((a.get("rule") or {}).get("id")), str((a.get("health") or {}).get("key")))] = a["_id"]
        self._loaded = True

    def raise_(self, rule_id: str, key: str, severity: str, detail: str, **fields: Any) -> dict[str, Any] | None:
        if (rule_id, key) in self.open:
            return None
        name, techniques, tactic = CHECKS[rule_id]
        now = store.now_iso()
        alert: dict[str, Any] = {
            "@timestamp": now,
            "alert": {"id": store.new_id(), "status": "open", "source": "health"},
            "rule": {"id": rule_id, "name": f"{name}: {key}", "description": detail, "type": "health",
                     "severity": severity, "tags": ["platform", "health"],
                     "mitre": {"tactic": tactic, "technique": techniques}},
            "severity": severity, "severity_score": SEVERITY_SCORE[severity],
            "risk_score": float(SEVERITY_SCORE[severity] * 25), "count": 1,
            "health": {"key": key, "detail": detail, **{k: v for k, v in fields.items() if k not in ("host", "agent", "asset")}},
            "first_event_time": now, "metrics": {"ttd_seconds": 0.0},
        }
        for k in ("host", "agent", "asset"):
            if fields.get(k):
                alert[k] = fields[k]
        alert["priority"] = prio.policy().priority(severity, (alert.get("asset") or {}).get("criticality"))
        alert["message"] = f"[{severity.upper()}] {alert['rule']['name']} | {detail}"
        self.open[(rule_id, key)] = alert["alert"]["id"]
        log.warning("HEALTH %s", alert["message"])
        self.emit(alert)
        return alert

    def recover(self, rule_id: str, key: str, text: str) -> bool:
        """Sự cố hết: ghi vào lịch sử alert đang mở (analyst đóng, có kết luận), lần sau bị lại thì mở alert mới."""
        aid = self.open.pop((rule_id, key), None)
        if not aid:
            return False
        now = store.now_iso()
        try:
            self.es.update(index=settings.IDX_ALERTS, id=aid, retry_on_conflict=3, script={"lang": "painless", "source": (
                "if (ctx._source.alert.history == null) { ctx._source.alert.history = new ArrayList(); }"
                "ctx._source.alert.history.add(['at': params.now, 'by': 'hệ thống', 'text': params.text]);"
                "ctx._source.health.recovered_at = params.now;"), "params": {"now": now, "text": text}})
        except Exception as e:  # noqa: BLE001
            log.warning("không ghi được hồi phục vào alert %s: %s", aid, e)
        log.info("HEALTH hồi phục %s %s: %s", rule_id, key, text)
        return True

    # ------------------------------------------------------------------ các phép kiểm tra
    def run(self) -> None:
        if not self._loaded:
            self.load_open()
        for check in (self.check_agents, self.check_sources, self.check_kafka, self.check_elasticsearch,
                      self.check_snapshots):
            try:
                check()
            except Exception as e:  # noqa: BLE001 - một phép kiểm tra lỗi không chặn các phép khác
                log.warning("kiểm tra sức khỏe %s lỗi: %s", check.__name__, e)

    def _asset(self, *keys: Any) -> dict[str, Any] | None:
        if not self.assets:
            return None
        for k in keys:
            a = self.assets.by_key.get(str(k).lower()) if k else None
            if a:
                return {"id": a.get("id"), "criticality": a.get("criticality", "medium")}
        return None

    def check_agents(self) -> None:
        now = self.clock()
        agents = store.list_agents(self.es)
        if not agents:
            return
        newest = max((_parse(a.get("synced_at")) or 0) for a in agents)
        stale = now - newest > max(settings.AGENT_OFFLINE_SECONDS * 3, 300)
        if settings.WAZUH_API_PASSWORD and stale:
            self.raise_("HLT-004", "wazuh-manager", "high",
                        f"SOAR không cập nhật được trạng thái agent từ Wazuh API {int((now - newest) / 60)} phút "
                        f"(lần cuối {_iso(newest)}): không biết agent nào đang mất kết nối, lệnh phản ứng có thể không tới")
            return                                  # trạng thái agent không còn tin được
        self.recover("HLT-004", "wazuh-manager", "SOAR đồng bộ lại được trạng thái agent từ Wazuh")
        limit = settings.AGENT_DOWN_MINUTES * 60
        for a in agents:
            name = a.get("hostname") or a.get("agent_id")
            seen = _parse(a.get("last_seen"))
            down = a.get("wazuh_status") == "disconnected" and seen is not None and now - seen > limit
            if down:
                asset = self._asset(a.get("agent_id"), a.get("hostname"))
                sev = "high" if asset and asset["criticality"] in ("high", "critical") else "medium"
                self.raise_("HLT-001", str(name), sev,
                            f"agent {a.get('agent_id')} ({name}, {a.get('ip') or 'không rõ IP'}) mất kết nối từ "
                            f"{_iso(seen)} ({int((now - seen) / 60)} phút): máy tắt, mất mạng, dịch vụ agent bị dừng "
                            "hoặc bị kẻ tấn công vô hiệu hóa", host={"name": name}, agent={"id": a.get("agent_id")},
                            asset=asset, last_seen=_iso(seen))
            elif a.get("wazuh_status") == "active":
                self.recover("HLT-001", str(name), "agent kết nối lại với wazuh-manager")

    def check_sources(self) -> None:
        """So lưu lượng từng nguồn (agent.id: Wazuh agent hoặc syslog-<ip>) với trung bình 7 ngày."""
        now = self.clock()
        silent_s = settings.SOURCE_SILENT_MINUTES * 60
        res = self.es.search(index=f"{settings.IDX_EVENTS}-*", size=0, query={"range": {"@timestamp": {
            "gte": _iso(now - 7 * 86400)}}}, aggs={"src": {"terms": {"field": "agent.id", "size": 1000}, "aggs": {
                "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                "hour": {"filter": {"range": {"@timestamp": {"gte": _iso(now - 3600)}}}},
                "host": {"terms": {"field": "host.name", "size": 1}}}}})
        docs = []
        for b in res["aggregations"]["src"]["buckets"]:
            src = str(b["key"])
            if src in SKIP_SOURCES:
                continue
            first, last = b["first"].get("value"), b["last"].get("value")
            if first is None or last is None:
                continue
            first, last = first / 1000, last / 1000
            host = (b["host"]["buckets"] or [{"key": src}])[0]["key"]
            span = max(now - first, 3600.0)
            rate_h = b["doc_count"] / (span / 3600)            # event / giờ trung bình kể từ khi nguồn xuất hiện (<= 7 ngày)
            hour = b["hour"]["doc_count"]
            status = "ok"
            expected_silent = rate_h * silent_s / 3600
            asset = self._asset(src, host)
            if now - last > silent_s and expected_silent >= settings.SOURCE_MIN_EXPECTED:
                status = "silent"
                self.raise_("HLT-002", src, "high" if asset and asset["criticality"] in ("high", "critical") else "medium",
                            f"nguồn {src} ({host}) không gửi event nào từ {_iso(last)} ({int((now - last) / 60)} phút), "
                            f"trung bình 7 ngày {rate_h:.0f} event/giờ", host={"name": host}, asset=asset,
                            expected_per_hour=round(rate_h, 1), last_event=_iso(last))
            else:
                self.recover("HLT-002", src, f"nguồn {src} gửi event trở lại")
            # lệch lưu lượng: chỉ xét nguồn đã có đủ 1 ngày dữ liệu và đủ lớn
            if span >= 86400 and rate_h >= settings.VOLUME_MIN_PER_HOUR and status == "ok":
                dev = (hour - rate_h) / rate_h
                if abs(dev) > settings.VOLUME_DEVIATION:
                    status = "deviation"
                    if now - self.last_volume.get(src, 0) > 6 * 3600:
                        self.last_volume[src] = now
                        self.open.pop(("HLT-003", src), None)     # báo lại tối đa 6 giờ / lần dù alert cũ chưa đóng
                        self.raise_("HLT-003", src, "low",
                                    f"nguồn {src} ({host}) gửi {hour} event trong 1 giờ qua, "
                                    f"{'cao' if dev > 0 else 'thấp'} hơn trung bình 7 ngày ({rate_h:.0f}/giờ) "
                                    f"{abs(dev):.0%}", host={"name": host}, asset=asset,
                                    expected_per_hour=round(rate_h, 1), last_hour=hour)
            docs.append({"_id": src, "source": src, "host": host, "status": status, "last_event": _iso(last),
                         "first_event_7d": _iso(first), "events_7d": b["doc_count"], "last_hour": hour,
                         "expected_per_hour": round(rate_h, 1), "checked_at": _iso(now), "@timestamp": _iso(now)})
        if docs:
            store.bulk_index(self.es, ({"_index": IDX_SOURCES, "_id": d.pop("_id"), "_source": d} for d in docs))

    def check_kafka(self) -> None:
        if not self.kafka_lag:
            return
        now = self.clock()
        for group, lag in self.kafka_lag().items():
            if lag > settings.KAFKA_LAG_MAX_MESSAGES:
                start = self.lag_since.setdefault(group, now)
                if now - start >= settings.KAFKA_LAG_MINUTES * 60:
                    self.raise_("HLT-005", group, "high",
                                f"consumer group {group} tụt sau {lag} message liên tục {int((now - start) / 60)} phút: "
                                "event / alert tới chậm, phát hiện và phản ứng bị trễ", lag=lag)
            else:
                self.lag_since.pop(group, None)
                self.recover("HLT-005", group, f"consumer group {group} bắt kịp (còn {lag} message)")

    def check_elasticsearch(self) -> None:
        health = self.es.cluster.health()
        status = health.get("status")
        if status == "red":
            self.raise_("HLT-006", "cluster", "critical", "cluster Elasticsearch trạng thái RED: có shard chính không "
                        "khả dụng, mất dữ liệu ghi / tìm kiếm", status=status)
        else:
            self.recover("HLT-006", "cluster", f"cluster Elasticsearch trở lại {status}")
        stats = self.es.nodes.stats(metric="fs")
        for node in (stats.get("nodes") or {}).values():
            fs = (node.get("fs") or {}).get("total") or {}
            total, avail = fs.get("total_in_bytes"), fs.get("available_in_bytes")
            if not total:
                continue
            used = 100.0 * (1 - avail / total)
            key = f"disk:{node.get('name')}"
            if used >= settings.ES_DISK_MAX_PCT:
                self.raise_("HLT-006", key, "critical" if used >= 90 else "high",
                            f"đĩa dữ liệu của node {node.get('name')} đã dùng {used:.0f}% (ngưỡng "
                            f"{settings.ES_DISK_MAX_PCT}%): ES ngừng ghi index ở 95% (flood stage)", disk_used_pct=round(used, 1))
            else:
                self.recover("HLT-006", key, f"đĩa node {node.get('name')} còn {100 - used:.0f}% trống")


    def check_snapshots(self) -> None:
        now = self.clock()
        try:
            pol = self.es.slm.get_lifecycle(policy_id=SLM_POLICY).get(SLM_POLICY) or {}
        except Exception as e:  # noqa: BLE001 - NotFound: es-setup chưa tạo chính sách (hệ thống cũ chưa chạy lại es-setup)
            if "404" in str(e) or "not_found" in str(e) or "NotFound" in type(e).__name__:
                self.raise_("HLT-007", SLM_POLICY, "medium", "chưa có chính sách snapshot daily-snapshots: chạy lại "
                            "`docker compose up -d --force-recreate es-setup`; hiện KHÔNG có bản sao lưu nào")
                return
            raise
        ok = ((pol.get("last_success") or {}).get("time") or 0) / 1000
        bad = ((pol.get("last_failure") or {}).get("time") or 0) / 1000
        created = (pol.get("modified_date_millis") or 0) / 1000
        max_age = settings.SNAPSHOT_MAX_AGE_HOURS * 3600
        if bad > ok:
            why = ((pol.get("last_failure") or {}).get("details") or "")[:300]
            self.raise_("HLT-007", SLM_POLICY, "high", f"lần snapshot gần nhất ({_iso(bad)}) thất bại: {why}",
                        last_failure=_iso(bad))
        elif now - max(ok, created) > max_age:
            self.raise_("HLT-007", SLM_POLICY, "high",
                        f"không có snapshot thành công trong {settings.SNAPSHOT_MAX_AGE_HOURS:g} giờ qua "
                        f"(lần gần nhất: {_iso(ok) if ok else 'chưa có'})", last_success=_iso(ok) if ok else None)
        else:
            self.recover("HLT-007", SLM_POLICY, f"snapshot thành công lúc {_iso(ok)}" if ok else "chính sách snapshot đã có")


def kafka_lag_reader(groups: dict[str, list[str]]) -> Callable[[], dict[str, int]]:
    """Số message mỗi consumer group còn chưa xử lý (tổng high watermark - offset đã commit trên mọi partition).
    Không tham gia group (không subscribe), chỉ đọc offset."""
    from confluent_kafka import Consumer, TopicPartition

    def read() -> dict[str, int]:
        out = {}
        for group, topics in groups.items():
            c = Consumer({"bootstrap.servers": settings.KAFKA_BOOTSTRAP, "group.id": group,
                          "enable.auto.commit": False})
            try:
                parts = [TopicPartition(t, p) for t in topics
                         for p in c.list_topics(t, timeout=5).topics[t].partitions]
                lag = 0
                for tp in c.committed(parts, timeout=5):
                    low, high = c.get_watermark_offsets(tp, timeout=5)
                    lag += high - (tp.offset if tp.offset >= 0 else low)
                out[group] = lag
            finally:
                c.close()
        return out
    return read
