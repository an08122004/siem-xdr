"""Sinh Grafana dashboard JSON cho SIEM/XDR (chạy lại khi muốn chỉnh bố cục):
    python tools/gen_dashboard.py
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "grafana" / "dashboards" / "siem-overview.json"

EV = {"type": "elasticsearch", "uid": "siem-events"}
AL = {"type": "elasticsearch", "uid": "siem-alerts"}
AC = {"type": "elasticsearch", "uid": "siem-actions"}
SEV_COLORS = {"low": "blue", "medium": "yellow", "high": "orange", "critical": "red"}
_id = [0]


def pid():
    _id[0] += 1
    return _id[0]


def date_hist(field="@timestamp"):
    return {"id": "2", "type": "date_histogram", "field": field, "settings": {"interval": "auto", "min_doc_count": "0"}}


def terms(field, size=10, id_="3"):
    return {"id": id_, "type": "terms", "field": field,
            "settings": {"size": str(size), "order": "desc", "orderBy": "_count", "min_doc_count": "1"}}


def target(ds, query="", bucket=None, metric=None, ref="A", time_field="@timestamp", alias=""):
    return {"refId": ref, "datasource": ds, "query": query, "alias": alias, "timeField": time_field,
            "metrics": [metric or {"id": "1", "type": "count"}], "bucketAggs": bucket if bucket is not None else [date_hist(time_field)]}


def stat(title, ds, query, x, y, color="blue", w=4):
    return {"id": pid(), "type": "stat", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": 4},
            "targets": [target(ds, query)],
            "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False}, "colorMode": "background",
                        "graphMode": "area", "textMode": "value"},
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": color}, "unit": "short"}, "overrides": []}}


def timeseries(title, ds, query, split, x, y, w=12, h=8, stack=True, overrides=None):
    return {"id": pid(), "type": "timeseries", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [terms(split, 10), date_hist()])],
            "fieldConfig": {"defaults": {"custom": {"drawStyle": "bars" if stack else "line", "fillOpacity": 70 if stack else 15,
                                                    "stacking": {"mode": "normal" if stack else "none"}, "lineWidth": 1}},
                            "overrides": overrides or []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}}


def pie(title, ds, query, field, x, y, w=6, h=8, size=10):
    return {"id": pid(), "type": "piechart", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [terms(field, size)])],
            "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": ""}, "pieType": "donut",
                        "legend": {"displayMode": "table", "placement": "right", "values": ["value"]}}}


def bars(title, ds, query, field, x, y, w=6, h=8, size=10):
    return {"id": pid(), "type": "bargauge", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [terms(field, size)])],
            "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": ""}, "orientation": "horizontal",
                        "displayMode": "gradient", "showUnfilled": True},
            "fieldConfig": {"defaults": {"color": {"mode": "continuous-YlRd"}}, "overrides": []}}


def table(title, ds, query, fields, x, y, w=24, h=10, time_field="@timestamp"):
    return {"id": pid(), "type": "table", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [], {"id": "1", "type": "raw_data", "settings": {"size": "200"}}, time_field=time_field)],
            "transformations": [{"id": "filterFieldsByName", "options": {"include": {"names": fields}}},
                                {"id": "organize", "options": {"indexByName": {f: i for i, f in enumerate(fields)}}}],
            "fieldConfig": {"defaults": {"custom": {"filterable": True}}, "overrides": [
                {"matcher": {"id": "byName", "options": "severity"},
                 "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                                {"id": "mappings", "value": [{"type": "value", "options": {
                                    k: {"color": c, "index": i} for i, (k, c) in enumerate(SEV_COLORS.items())}}]}]}]},
            "options": {"showHeader": True, "sortBy": [{"displayName": fields[0], "desc": True}]}}


def row(title, y):
    return {"id": pid(), "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


sev_overrides = [{"matcher": {"id": "byName", "options": k},
                  "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]} for k, c in SEV_COLORS.items()]

panels = [
    row("Tổng quan", 0),
    stat("Tổng event", EV, "", 0, 1, "blue"),
    stat("Tổng alert", AL, "", 4, 1, "purple"),
    stat("Alert critical", AL, "severity:critical", 8, 1, "red"),
    stat("Alert high", AL, "severity:high", 12, 1, "orange"),
    stat("Case đang mở", {"type": "elasticsearch", "uid": "siem-cases"}, "status:(open OR in_progress OR contained)", 16, 1, "yellow"),
    stat("Lệnh phản ứng XDR", AC, "", 20, 1, "green"),
    timeseries("Alert theo mức độ", AL, "", "severity", 0, 5, overrides=sev_overrides),
    timeseries("Event theo loại (event.category)", EV, "", "event.category", 12, 5),
    row("Phát hiện (Detection)", 13),
    bars("Top rule kích hoạt", AL, "", "rule.name", 0, 14, w=8, size=15),
    pie("MITRE ATT&CK tactic", AL, "", "rule.mitre.tactic", 8, 14),
    bars("Top IP tấn công (từ alert)", AL, "", "source.ip", 14, 14, w=5),
    pie("Host bị nhắm tới", AL, "", "host.name", 19, 14, w=5),
    table("Alert mới nhất", AL, "", ["@timestamp", "severity", "rule.id", "rule.name", "source.ip", "user.name",
                                     "host.name", "agent.id", "risk_score", "alert.status", "message"], 0, 22),
    row("Telemetry", 32),
    timeseries("HTTP status code (Apache)", EV, "event.module:apache", "http.response.status_code", 0, 33, w=8),
    timeseries("Xác thực thất bại theo IP", EV, "event.category:authentication AND event.outcome:failure", "source.ip", 8, 33, w=8),
    pie("Nguồn dữ liệu (event.module)", EV, "", "event.module", 16, 33, w=8),
    bars("Top URL bị truy cập", EV, "event.category:web", "url.path", 0, 41, w=12, size=15),
    bars("Kết nối bị firewall chặn (IP nguồn)", EV, "event.action:deny", "source.ip", 12, 41, w=12),
    row("Phản ứng (XDR / SOAR)", 49),
    table("Lệnh phản ứng gần đây", AC, "", ["created_at", "agent_id", "type", "target", "source", "status", "expires_at", "output"],
          0, 50, h=9, time_field="created_at"),
]

dash = {
    "uid": "siem-overview", "title": "SIEM/XDR — Tổng quan SOC", "tags": ["siem", "xdr", "soc"],
    "timezone": "browser", "schemaVersion": 39, "version": 1, "refresh": "10s",
    "time": {"from": "now-1h", "to": "now"}, "editable": True, "panels": panels,
    "templating": {"list": []}, "annotations": {"list": []},
}
OUT.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"OK: {OUT} ({len(panels)} panels)")
