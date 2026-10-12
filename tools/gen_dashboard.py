"""Sinh Grafana dashboard JSON cho SIEM/XDR (chạy lại khi muốn chỉnh bố cục):
    python tools/gen_dashboard.py

  siem-overview     Tổng quan SOC (trang Tổng quan của console nhúng dashboard này)
  siem-investigate  Điều tra một thực thể: mọi panel lọc theo biến q (Lucene) do console truyền vào,
                    vd source.ip:"203.0.113.9" hoặc host.name:"demo-web" (trang Điều tra của console)
Bảng alert / case có liên kết "Mở trên SOC console" (/go/alert/<id>, /go/case/<id>, xem manager/api.py).
"""
import json
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent / "grafana" / "dashboards"

EV = {"type": "elasticsearch", "uid": "siem-events"}
AL = {"type": "elasticsearch", "uid": "siem-alerts"}
AC = {"type": "elasticsearch", "uid": "siem-actions"}
CS = {"type": "elasticsearch", "uid": "siem-cases"}
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
            # min 0: khi chỉ có 1 giá trị, thanh không có màu (min = max). Grafana ẩn tên khi chỉ có 1 giá trị -> panel
            # thường chỉ có 1 giá trị (vd IP tấn công trong lab) dùng pie, chú giải luôn có tên
            "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": ""}, "orientation": "horizontal",
                        "displayMode": "gradient", "showUnfilled": True},
            "fieldConfig": {"defaults": {"color": {"mode": "continuous-YlRd"}, "min": 0}, "overrides": []}}


def color_cells(field, colors):
    """Tô màu ô của cột `field` theo giá trị (vd severity, event.outcome)."""
    return {"matcher": {"id": "byName", "options": field},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                           {"id": "mappings", "value": [{"type": "value", "options": {
                               k: {"color": c, "index": i} for i, (k, c) in enumerate(colors.items())}}]}]}


def table(title, ds, query, fields, x, y, w=24, h=10, time_field="@timestamp", overrides=None, rename=None,
          sort=None, size=200, cell_height="sm"):
    """rename: tên cột hiển thị (tên trường gốc vẫn dùng được trong liên kết). sort: (cột, giảm dần?)."""
    col, desc = sort or (fields[0], True)
    return {"id": pid(), "type": "table", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [], {"id": "1", "type": "raw_data", "settings": {"size": str(size)}}, time_field=time_field)],
            "transformations": [{"id": "filterFieldsByName", "options": {"include": {"names": fields}}},
                                {"id": "organize", "options": {"indexByName": {f: i for i, f in enumerate(fields)},
                                                               "renameByName": rename or {}}}],
            "fieldConfig": {"defaults": {"custom": {"filterable": True}},
                            "overrides": [color_cells("severity", SEV_COLORS), *(overrides or [])]},
            "options": {"showHeader": True, "cellHeight": cell_height,
                        "sortBy": [{"displayName": (rename or {}).get(col, col), "desc": desc}]}}


def wrap(field, width=None):
    """Cột chữ dài (điều kiện, YAML, lý do): xuống dòng thay vì cắt."""
    props = [{"id": "custom.cellOptions", "value": {"type": "auto", "wrapText": True}}]
    return {"matcher": {"id": "byName", "options": field},
            "properties": props + ([{"id": "custom.width", "value": width}] if width else [])}


def inspect(field, px=None):
    """Cột chữ dài hiển thị 1 dòng, bấm biểu tượng con mắt để xem đầy đủ."""
    return {"matcher": {"id": "byName", "options": field},
            "properties": [{"id": "custom.inspect", "value": True}] + ([{"id": "custom.width", "value": px}] if px else [])}


def width(field, px):
    return {"matcher": {"id": "byName", "options": field}, "properties": [{"id": "custom.width", "value": px}]}


def link_to(field, title, url):
    return {"matcher": {"id": "byName", "options": field},
            "properties": [{"id": "links", "value": [{"title": title, "url": url, "targetBlank": True}]}]}


def hide(field):
    return {"matcher": {"id": "byName", "options": field}, "properties": [{"id": "custom.hidden", "value": True}]}


def all_time(panel):
    """Panel trạng thái hiện tại (vd case đang mở) không lọc theo khoảng thời gian của dashboard: datasource case lọc theo
    created_at, nên xem "1 giờ" thì case mở từ hôm qua biến mất khỏi ô "Case đang mở" (số khác hẳn menu console)."""
    return panel | {"timeFrom": "10y", "hideTimeOverride": True}


def row(title, y):
    return {"id": pid(), "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def console_link(kind, id_field, *columns):
    """Bấm vào ô của các cột `columns` -> mở alert / case trên SOC console. Mở tab mới khi xem Grafana riêng; khi Grafana
    nằm trong console, console bắt cú bấm và mở ngay chi tiết tại chỗ. Cột id được ẩn đi."""
    links = [{"title": "Mở trên SOC console", "url": f'/go/{kind}/${{__data.fields["{id_field}"]}}', "targetBlank": True}]
    return [*({"matcher": {"id": "byName", "options": c}, "properties": [{"id": "links", "value": links}]} for c in columns),
            {"matcher": {"id": "byName", "options": id_field}, "properties": [{"id": "custom.hidden", "value": True}]}]


CASE_COLORS = {"open": "red", "in_progress": "orange", "contained": "yellow", "closed": "green", "false_positive": "blue"}


sev_overrides = [{"matcher": {"id": "byName", "options": k},
                  "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]} for k, c in SEV_COLORS.items()]
OUTCOME_COLORS = {"success": "green", "failure": "red"}
outcome_overrides = [{"matcher": {"id": "byName", "options": k},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                     for k, c in OUTCOME_COLORS.items()]

# Phiên đăng nhập: đăng nhập hệ thống (SSH, PAM, Windows logon 4624/4625 — event.category authentication)
# và đăng nhập form web (POST tới đường dẫn login — access log không có tên tài khoản, chỉ có IP và mã HTTP)
AUTH = "event.category:authentication"
WEB_LOGIN = "event.category:web AND http.request.method:POST AND url.path:*login*"
PRIVILEGED = "user.name:(root OR Administrator OR admin)"

panels = [
    row("Tổng quan", 0),
    stat("Tổng event", EV, "", 0, 1, "blue"),
    stat("Tổng alert", AL, "", 4, 1, "purple"),
    stat("Alert critical", AL, "severity:critical", 8, 1, "red"),
    stat("Alert high", AL, "severity:high", 12, 1, "orange"),
    all_time(stat("Case đang mở", CS, "status:(open OR in_progress OR contained)", 16, 1, "yellow")),
    stat("Lệnh phản ứng XDR", AC, "", 20, 1, "green"),
    timeseries("Alert theo mức độ", AL, "", "severity", 0, 5, overrides=sev_overrides),
    timeseries("Event theo loại (event.category)", EV, "", "event.category", 12, 5),
    row("Phát hiện (Detection)", 13),
    bars("Top rule kích hoạt", AL, "", "rule.name", 0, 14, w=8, size=15),
    pie("MITRE ATT&CK tactic", AL, "", "rule.mitre.tactic", 8, 14),
    pie("Top IP tấn công (từ alert)", AL, "", "source.ip", 14, 14, w=5),
    pie("Host bị nhắm tới", AL, "", "host.name", 19, 14, w=5),
    table("Alert mới nhất — bấm tên rule để mở trên console", AL, "",
          ["@timestamp", "severity", "rule.id", "rule.name", "source.ip", "user.name", "host.name", "agent.id",
           "risk_score", "alert.status", "message", "alert.id"], 0, 22,
          overrides=console_link("alert", "alert.id", "rule.id", "rule.name")),
    row("Telemetry", 32),
    timeseries("HTTP status code (Apache)", EV, "event.module:apache", "http.response.status_code", 0, 33, w=8),
    timeseries("Xác thực thất bại theo IP", EV, "event.category:authentication AND event.outcome:failure", "source.ip", 8, 33, w=8),
    pie("Nguồn dữ liệu (event.module)", EV, "", "event.module", 16, 33, w=8),
    bars("Top URL bị truy cập", EV, "event.category:web", "url.path", 0, 41, w=12, size=15),
    bars("Kết nối bị firewall chặn (IP nguồn)", EV, "event.action:deny", "source.ip", 12, 41, w=12),
    row("Phiên đăng nhập", 49),
    stat("Đăng nhập thành công", EV, f"{AUTH} AND event.outcome:success", 0, 50, "green", w=6),
    stat("Đăng nhập thất bại", EV, f"{AUTH} AND event.outcome:failure", 6, 50, "red", w=6),
    stat("Tài khoản đặc quyền đăng nhập được", EV, f"{AUTH} AND event.outcome:success AND {PRIVILEGED}", 12, 50,
         "purple", w=6),
    stat("Đăng nhập form web bị từ chối", EV, f"{WEB_LOGIN} AND http.response.status_code:(401 OR 403)", 18, 50,
         "orange", w=6),
    timeseries("Đăng nhập hệ thống theo kết quả", EV, AUTH, "event.outcome", 0, 54, overrides=outcome_overrides),
    timeseries("Đăng nhập form web theo IP nguồn", EV, WEB_LOGIN, "source.ip", 12, 54),
    bars("Tài khoản đăng nhập thất bại nhiều nhất", EV, f"{AUTH} AND event.outcome:failure", "user.name", 0, 62),
    bars("IP nguồn đăng nhập thành công", EV, f"{AUTH} AND event.outcome:success", "source.ip", 6, 62),
    pie("Đăng nhập theo máy", EV, AUTH, "host.name", 12, 62),
    pie("Hình thức đăng nhập", EV, AUTH, "event.action", 18, 62),
    table("Phiên đăng nhập gần đây", EV, f"{AUTH} OR ({WEB_LOGIN})",
          ["@timestamp", "event.outcome", "user.name", "source.ip", "host.name", "event.action", "auth.method",
           "winlog.logon.type", "url.path", "http.response.status_code", "message"], 0, 70,
          overrides=[color_cells("event.outcome", OUTCOME_COLORS)]),
    row("Phản ứng (XDR / SOAR)", 80),
    table("Lệnh phản ứng gần đây", AC, "", ["created_at", "agent_id", "type", "target", "source", "status", "expires_at", "output"],
          0, 81, h=9, time_field="created_at"),
    all_time(table("Case đang mở — bấm tiêu đề để mở trên console", CS, "status:(open OR in_progress OR contained)",
                   ["created_at", "priority", "severity", "title", "entity", "alert_count", "assignee", "status", "id"],
                   0, 90, h=9, time_field="created_at",
                   overrides=[color_cells("status", CASE_COLORS), *console_link("case", "id", "title")])),
]


def dashboard(uid, title, panels, refresh="30s", time_from="now-1h", templating=None):
    return {"uid": uid, "title": title, "tags": ["siem", "xdr", "soc"], "timezone": "browser", "schemaVersion": 39,
            "version": 1, "refresh": refresh, "time": {"from": time_from, "to": "now"}, "editable": True,
            "panels": panels, "templating": {"list": templating or []}, "annotations": {"list": []}}


# ------------------------------------------------------------------ Điều tra thực thể
# Biến q (Lucene) do console đặt khi bấm "Điều tra" trên alert / agent / case: IP -> source.ip hoặc destination.ip,
# máy -> host.name, tài khoản -> user.name. Để trống (*) là xem toàn bộ.
Q = "(${q:raw})"
investigate = [
    row("Thực thể: ${q}", 0),
    stat("Event", EV, Q, 0, 1, "blue", w=6),
    stat("Alert", AL, Q, 6, 1, "purple", w=6),
    stat("Alert critical / high", AL, f"{Q} AND severity:(critical OR high)", 12, 1, "red", w=6),
    stat("Đăng nhập thất bại", EV, f"{Q} AND {AUTH} AND event.outcome:failure", 18, 1, "orange", w=6),
    timeseries("Event theo loại", EV, Q, "event.category", 0, 5),
    timeseries("Alert theo mức độ", AL, Q, "severity", 12, 5, overrides=sev_overrides),
    bars("Hành động (event.action)", EV, Q, "event.action", 0, 13, w=6),
    bars("URL bị truy cập", EV, f"{Q} AND event.category:web", "url.path", 6, 13, w=6),
    bars("Tiến trình", EV, f"{Q} AND event.category:process", "process.name", 12, 13, w=6),
    pie("IP liên quan", EV, Q, "source.ip", 18, 13, w=6),
    table("Alert của thực thể — bấm tên rule để mở trên console", AL, Q,
          ["@timestamp", "severity", "rule.id", "rule.name", "source.ip", "user.name", "host.name", "alert.status",
           "alert.id"], 0, 21, h=9, overrides=console_link("alert", "alert.id", "rule.id", "rule.name")),
    table("Event gần đây", EV, Q, ["@timestamp", "event.category", "event.action", "event.outcome", "source.ip",
                                   "user.name", "host.name", "process.name", "url.original", "message"], 0, 30, h=12),
]
q_var = {"type": "textbox", "name": "q", "label": "Bộ lọc (Lucene)", "query": "*",
         "current": {"text": "*", "value": "*"}, "options": [{"selected": True, "text": "*", "value": "*"}]}


# ------------------------------------------------------------------ Thư viện rule (tra cứu + so sánh với đề xuất AI)
# Dữ liệu: index siem-rules do manager đồng bộ (server/siem/rules_catalog.py). Danh mục không theo thời gian -> dashboard
# xem 20 năm; số alert 24 giờ / 7 ngày của từng rule đã tính sẵn trong danh mục.
RU = {"type": "elasticsearch", "uid": "siem-rules"}
CATALOG = "origin:${origin:raw} AND mitre.tactic:$tactic AND tags:$tag AND fields:$field AND (${q:raw})"
PICKED = "proposal.pick:${proposal:lucene}"


def terms_var(name, label, field, query="origin:(rule OR ai_proposal OR exception)", all_=True, size=300):
    return {"type": "query", "name": name, "label": label, "datasource": RU, "refresh": 1, "sort": 1,
            "query": json.dumps({"find": "terms", "field": field, "query": query, "size": size}, ensure_ascii=False),
            "includeAll": all_, "multi": all_, "allValue": "*" if all_ else None,
            "current": {"text": "All", "value": "$__all"} if all_ else {}}


rules_vars = [
    {"type": "custom", "name": "origin", "label": "Hiển thị",
     "query": "Tất cả : (rule OR ai_proposal OR exception),Rule đang chạy : rule,Đề xuất AI : ai_proposal,Ngoại lệ : exception",
     "current": {"text": "Tất cả", "value": "(rule OR ai_proposal OR exception)"}},
    terms_var("tactic", "MITRE tactic", "mitre.tactic"),
    terms_var("tag", "Tag", "tags"),
    terms_var("field", "Trường log", "fields"),
    {"type": "textbox", "name": "q", "label": "Tìm (Lucene)", "query": "*", "current": {"text": "*", "value": "*"},
     "options": [{"selected": True, "text": "*", "value": "*"}]},
    terms_var("proposal", "Đề xuất cần so sánh", "proposal.pick", query="origin:ai_proposal", all_=False, size=500),
]
CATALOG_COLS = ["origin_label", "rule.id", "rule.name", "severity", "type", "mitre.tactic", "technique_text", "tags_text",
                "fields_text", "condition_text", "alerts.h24", "alerts.d7", "alerts.last", "proposal.status_label",
                "proposal.test", "proposal.fp", "proposal.alerts_per_day", "file", "proposal.id"]
most_alerts = {"id": pid(), "type": "bargauge", "title": "Rule kêu nhiều nhất (7 ngày)", "datasource": RU,
               "gridPos": {"x": 16, "y": 5, "w": 8, "h": 8},
               "targets": [{"refId": "A", "datasource": RU, "query": "origin:rule AND alerts.d7:>0", "timeField": "@timestamp",
                            "metrics": [{"id": "1", "type": "sum", "field": "alerts.d7"}],
                            "bucketAggs": [{"id": "3", "type": "terms", "field": "rule.name",
                                            "settings": {"size": "10", "order": "desc", "orderBy": "1", "min_doc_count": "1"}}]}],
               "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": ""},
                           "orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True},
               "fieldConfig": {"defaults": {"color": {"mode": "continuous-YlRd"}, "min": 0}, "overrides": []}}
rules_lib = [
    row("Tổng quan thư viện", 0),
    stat("Rule đang chạy", RU, "origin:rule", 0, 1, "blue"),
    stat("Rule do AI viết (đã duyệt)", RU, "origin:rule AND source:ai", 4, 1, "purple"),
    stat("Ngoại lệ đang áp dụng", RU, "origin:exception", 8, 1, "yellow"),
    stat("Đề xuất AI chờ duyệt", RU, "origin:ai_proposal AND proposal.status:pending", 12, 1, "orange"),
    stat("Đề xuất không đạt kiểm định", RU, "origin:ai_proposal AND proposal.passed:false", 16, 1, "red"),
    stat("Rule im lặng 7 ngày", RU, "origin:rule AND alerts.d7:0", 20, 1, "text"),
    pie("Rule theo MITRE tactic", RU, "origin:rule", "mitre.tactic", 0, 5, w=8),
    pie("Đề xuất AI theo trạng thái", RU, "origin:ai_proposal", "proposal.status_label", 8, 5, w=8),
    most_alerts,
    row("Danh sách rule, ngoại lệ, đề xuất AI — lọc bằng các ô phía trên", 13),
    table("Rule và đề xuất AI — bấm mã rule xem cảnh báo của rule, bấm trạng thái đề xuất để mở trên console",
          RU, CATALOG, CATALOG_COLS, 0, 14, h=16, size=500, sort=("rule.id", False),
          rename={"origin_label": "Nguồn", "rule.id": "Mã", "rule.name": "Tên", "severity": "Mức độ", "type": "Loại",
                  "mitre.tactic": "Tactic", "technique_text": "Kỹ thuật", "tags_text": "Tag", "fields_text": "Trường log",
                  "condition_text": "Điều kiện", "alerts.h24": "Alert 24h", "alerts.d7": "Alert 7 ngày",
                  "alerts.last": "Alert gần nhất", "proposal.status_label": "Trạng thái đề xuất",
                  "proposal.test": "Bắt mẫu kiểm tra", "proposal.fp": "Báo nhầm", "proposal.alerts_per_day": "Alert/ngày (ước tính)",
                  "file": "File"},
          overrides=[inspect("condition_text", 460), inspect("rule.name", 260), width("origin_label", 130),
                     inspect("fields_text", 200), hide("proposal.id"),
                     link_to("rule.id", "Xem cảnh báo của rule trên console", '/go/rule/${__data.fields["rule.id"]}'),
                     link_to("proposal.status_label", "Mở đề xuất trên console", '/go/proposal/${__data.fields["proposal.id"]}')]),
    row("So sánh đề xuất AI với rule hiện có — chọn đề xuất ở ô “Đề xuất cần so sánh”", 30),
    table("Đề xuất đã chọn", RU, f"origin:ai_proposal AND {PICKED}",
          ["proposal.kind_label", "rule.id", "rule.name", "proposal.status_label", "proposal.test", "proposal.fp",
           "proposal.alerts_per_day", "proposal.approvals", "mitre.tactic", "tags_text", "condition_text", "yaml", "proposal.id"],
          0, 31, h=6, cell_height="lg",
          rename={"proposal.kind_label": "Loại", "rule.id": "Mã", "rule.name": "Đề xuất", "proposal.status_label": "Trạng thái",
                  "proposal.test": "Bắt mẫu kiểm tra", "proposal.fp": "Báo nhầm", "proposal.alerts_per_day": "Alert/ngày",
                  "proposal.approvals": "Lượt duyệt", "mitre.tactic": "Tactic", "tags_text": "Tag",
                  "condition_text": "Điều kiện AI đề xuất", "yaml": "YAML"},
          overrides=[wrap("condition_text", 380), inspect("yaml", 160), wrap("rule.name", 240), hide("proposal.id"),
                     link_to("proposal.status_label", "Mở đề xuất trên console", '/go/proposal/${__data.fields["proposal.id"]}')]),
    table("Rule hiện có liên quan — điều kiện hai bên đặt cạnh nhau, xếp theo mức liên quan", RU, f"origin:comparison AND {PICKED}",
          ["score", "rule.id", "rule.name", "reasons_text", "condition_text", "proposal.condition_text", "alerts.d7"],
          0, 37, h=14, sort=("score", True), cell_height="lg",
          rename={"score": "Mức liên quan", "rule.id": "Mã", "rule.name": "Rule hiện có", "severity": "Mức độ",
                  "reasons_text": "Vì sao liên quan", "condition_text": "Điều kiện rule hiện có",
                  "proposal.condition_text": "Điều kiện AI đề xuất", "alerts.d7": "Alert 7 ngày"},
          overrides=[wrap("reasons_text", 230), wrap("condition_text", 300), wrap("proposal.condition_text", 300),
                     inspect("condition_text"), inspect("proposal.condition_text"), inspect("reasons_text"),
                     width("score", 90), width("rule.id", 90), wrap("rule.name", 170), link_to("rule.id", "Xem cảnh báo của rule trên console", '/go/rule/${__data.fields["rule.id"]}')]),
]

for uid, title, body, extra in (
        ("siem-overview", "SIEM/XDR — Tổng quan SOC", panels, {}),
        ("siem-investigate", "SIEM/XDR — Điều tra thực thể", investigate, {"templating": [q_var], "time_from": "now-24h"}),
        ("siem-rules", "SIEM/XDR — Thư viện rule", rules_lib, {"templating": rules_vars, "time_from": "now-20y", "refresh": "1m"})):
    out = DIR / f"{uid}.json"
    out.write_text(json.dumps(dashboard(uid, title, body, **extra), ensure_ascii=False, indent=2),
                   encoding="utf-8", newline="\n")
    print(f"OK: {out} ({len(body)} panels)")
