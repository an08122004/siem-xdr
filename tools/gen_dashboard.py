"""Sinh Grafana dashboard JSON cho SIEM/XDR (chạy lại khi muốn chỉnh bố cục):
    python tools/gen_dashboard.py

  siem-overview     Tổng quan SOC (trang Tổng quan của console nhúng dashboard này)
  siem-investigate  Điều tra một thực thể: mọi panel lọc theo biến q (Lucene) do console truyền vào,
                    vd source.ip:"203.0.113.9" hoặc host.name:"demo-web" (trang Điều tra của console)
Bảng alert / case có liên kết "Mở trên SOC console" (/go/alert/<id>, /go/case/<id>, xem manager/api.py).
"""
import json
import os
from pathlib import Path

# GEN_DASHBOARD_OUT: thư mục ghi thay thế (test so JSON đã commit với đầu ra của generator)
DIR = Path(os.environ.get("GEN_DASHBOARD_OUT") or Path(__file__).resolve().parent.parent / "grafana" / "dashboards")

EV = {"type": "elasticsearch", "uid": "siem-events"}
AL = {"type": "elasticsearch", "uid": "siem-alerts"}
AC = {"type": "elasticsearch", "uid": "siem-actions"}
CS = {"type": "elasticsearch", "uid": "siem-cases"}

# Màu theo token của console (server/siem/manager/static/console.html), kiểm bằng validator bảng màu trên nền panel
# #181b1f: hai khối màu nằm sát nhau (cột chồng) phải khác nhau rõ, cả với người mù màu đỏ-lục. Màu chỉ mang nghĩa
# (mức độ, kết quả, trạng thái); số liệu xếp hạng dùng một màu, giá trị lạ màu xám (không sinh màu mới).
# Khối và chữ tách riêng: đỏ critical của console (#e2474b) quá gần cam high khi hai khối liền nhau -> khối dùng #cc313a;
# chữ đỏ dùng #ea5a5d cho đủ tương phản 4.5:1.
SEV_MARK = {"critical": "#cc313a", "high": "#e7793a", "medium": "#e0b93b", "low": "#4f9dde"}
SEV_TEXT = {"critical": "#ea5a5d", "high": "#e7793a", "medium": "#e0b93b", "low": "#4f9dde"}
SEV_LABEL = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp"}
OK, ACCENT, NEUTRAL, MUTE = "#3fb27f", "#4f9dde", "#6b7280", "#8e95a3"
ST_NEW, ST_WORK, ST_DONE = "#ffb1b3", "#ffd38a", "#9fdcbf"     # chữ nhãn trạng thái, như .st.new / .work / .done của console
# nhiều đường cùng biểu đồ (xu hướng KPI): thứ tự cố định, đã kiểm định (các cặp liền kề phân biệt được, cả mù màu)
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"]
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


def stat(title, ds, query, x, y, w=4, spark=NEUTRAL):
    """Ô số: con số màu chữ thường (không tô nền), dưới là đường xu hướng nhỏ màu xám; ô mức độ dùng màu mức độ."""
    return {"id": pid(), "type": "stat", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": 4},
            "targets": [target(ds, query)], "maxDataPoints": 30,
            "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False}, "colorMode": "none",
                        "graphMode": "area", "textMode": "value", "justifyMode": "auto"},
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": spark}, "unit": "short", "decimals": 0},
                            "overrides": []}}


def series_colors(colors, labels=None):
    """Override màu cố định (và tên hiển thị) theo tên series: màu đi theo giá trị, không theo thứ hạng."""
    return [{"matcher": {"id": "byName", "options": k},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]
                           + ([{"id": "displayName", "value": labels[k]}] if labels and k in labels else [])}
            for k, c in colors.items()]


def timeseries(title, ds, query, split, x, y, w=12, h=8, colors=None, labels=None):
    """Cột chồng theo thời gian, mỗi giá trị của `split` một màu cố định. Chỉ cho trường ít giá trị biết trước (mức độ,
    kết quả); trường nhiều giá trị (IP, loại event) dùng bars(). `split` là list (nhãn, Lucene) thì gom bằng filters."""
    bucket = ({"id": "3", "type": "filters", "settings": {"filters": [{"label": k, "query": q} for k, q in split]}}
              if isinstance(split, list) else terms(split, 10))
    return {"id": pid(), "type": "timeseries", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [bucket, date_hist()])],
            "maxDataPoints": 48,                       # khoảng 48 cột trên trục: cột đủ dày để đọc, không mảnh như kim
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": MUTE}, "unit": "short", "decimals": 0,
                                         "custom": {"drawStyle": "bars", "fillOpacity": 90, "lineWidth": 0,
                                                    "barWidthFactor": 0.7, "stacking": {"mode": "normal"},
                                                    "showPoints": "never", "axisSoftMin": 0, "gradientMode": "none"}},
                            "overrides": series_colors(colors or {}, labels)},
            "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                        "tooltip": {"mode": "multi", "sort": "desc"}}}


def bars(title, ds, query, field, x, y, w=6, h=8, size=10, metric=None, sort_term=False, name_field=None):
    """Xếp hạng top N: bảng không tiêu đề cột, tên bên trái, bên phải thanh mảnh một màu kèm số màu chữ thường.
    Không dùng panel bar gauge: Grafana ẩn tên khi chỉ có 1 giá trị (vd 1 IP tấn công trong lab) hoặc khi thanh thấp."""
    agg = terms(field, size)
    if metric:
        agg["settings"]["orderBy"] = "1"             # xếp theo metric (vd tổng alert 7 ngày), không theo số document
    if sort_term:
        agg["settings"].update(order="asc", orderBy="_term")   # giá trị có thứ tự (P1..P4): giữ thứ tự, không xếp theo số
    aggs = [agg] + ([terms(name_field, 1, id_="4")] if name_field else [])    # cột thứ hai: tên đi kèm mã (mỗi mã một tên)
    return {"id": pid(), "type": "table", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, aggs, metric)],
            "options": {"showHeader": False, "cellHeight": "sm", "footer": {"show": False}},
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": ACCENT}, "min": 0, "unit": "short",
                                         "decimals": 0, "custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
                            "overrides": [{"matcher": {"id": "byType", "options": "number"},
                                           "properties": [{"id": "custom.cellOptions",
                                                           "value": {"type": "gauge", "mode": "basic",
                                                                     "valueDisplayMode": "text"}},
                                                          # cột thanh rộng cố định: hẹp hơn ~120px Grafana ẩn con số
                                                          {"id": "custom.width", "value": 130}]},
                                          # cột tên nhường chỗ (mặc định tối thiểu 150px chèn mất cột thanh ở panel hẹp)
                                          {"matcher": {"id": "byType", "options": "string"},
                                           "properties": [{"id": "custom.minWidth", "value": 50}]}]}}


def label_cells(field, values):
    """Cột trạng thái / mức độ: giá trị gốc -> nhãn tiếng Việt như console, chữ màu theo nghĩa (không tô nền cả ô).
    values: {giá trị: (nhãn, màu chữ)}."""
    return {"matcher": {"id": "byName", "options": field},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                           {"id": "mappings", "value": [{"type": "value", "options": {
                               k: {"text": t, "color": c, "index": i} for i, (k, (t, c)) in enumerate(values.items())}}]}]}


SEV_CELLS = {k: ("■ " + SEV_LABEL[k], SEV_TEXT[k]) for k in ("critical", "high", "medium", "low")}
PRIO_CELLS = {p: (p, SEV_TEXT[s]) for p, s in (("P1", "critical"), ("P2", "high"), ("P3", "medium"), ("P4", "low"))}
ALERT_CELLS = {"open": ("Mới", ST_NEW), "acknowledged": ("Đã xác nhận", ST_WORK), "in_progress": ("Đang xử lý", ST_WORK),
               "closed": ("Đã đóng", ST_DONE), "false_positive": ("Báo nhầm", ST_DONE)}
CASE_CELLS = {"open": ("Mới", ST_NEW), "in_progress": ("Đang xử lý", ST_WORK), "contained": ("Đã ngăn chặn", ST_WORK),
              "closed": ("Đã đóng", ST_DONE), "false_positive": ("Báo nhầm", ST_DONE)}
ACTION_CELLS = {"pending": ("Chờ gửi", ST_WORK), "sent": ("Đã gửi, chờ agent", ST_WORK), "success": ("Thành công", ST_DONE),
                "failed": ("Thất bại", ST_NEW), "timeout": ("Quá hạn", ST_NEW)}
OUTCOME_CELLS = {"success": ("Thành công", ST_DONE), "failure": ("Thất bại", ST_NEW)}


def table(title, ds, query, fields, x, y, w=24, h=10, time_field="@timestamp", overrides=None, rename=None,
          sort=None, size=200, cell_height="sm"):
    """rename: tên cột hiển thị, mặc định COLS (tên trường gốc vẫn dùng được trong liên kết). sort: (cột, giảm dần?)."""
    col, desc = sort or (fields[0], True)
    return {"id": pid(), "type": "table", "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(ds, query, [], {"id": "1", "type": "raw_data", "settings": {"size": str(size)}}, time_field=time_field)],
            "transformations": [{"id": "filterFieldsByName", "options": {"include": {"names": fields}}},
                                {"id": "organize", "options": {"indexByName": {f: i for i, f in enumerate(fields)},
                                                               "renameByName": rename or COLS}}],
            "fieldConfig": {"defaults": {"custom": {"filterable": True, "minWidth": 90}},   # mặc định 150px: bảng tràn ngang
                            "overrides": [label_cells("severity", SEV_CELLS), *(overrides or [])]},
            "options": {"showHeader": True, "cellHeight": cell_height,
                        "sortBy": [{"displayName": (rename or COLS).get(col, col), "desc": desc}]}}


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


# Tên cột tiếng Việt cho bảng (tên trường gốc vẫn dùng trong override và liên kết)
COLS = {"@timestamp": "Thời điểm", "created_at": "Tạo lúc", "severity": "Mức độ", "priority": "Ưu tiên",
        "rule.id": "Mã rule", "rule.name": "Cảnh báo", "source.ip": "IP nguồn", "user.name": "Tài khoản", "host.name": "Máy",
        "agent.id": "Agent", "agent_id": "Agent", "risk_score": "Rủi ro", "alert.status": "Trạng thái", "status": "Trạng thái",
        "message": "Nội dung", "event.category": "Loại", "event.action": "Hành động", "event.outcome": "Kết quả",
        "process.name": "Tiến trình", "url.original": "URL", "url.path": "URL", "auth.method": "Phương thức",
        "winlog.logon.type": "Kiểu logon", "http.response.status_code": "Mã HTTP", "type": "Lệnh", "target": "Đối tượng",
        "source": "Nguồn", "expires_at": "Hết hạn", "output": "Kết quả trả về", "title": "Tiêu đề", "entity": "Thực thể",
        "alert_count": "Số alert", "assignee": "Người xử lý"}
SEV_ORDER = ("critical", "high", "medium", "low")
sev_series = {"colors": {k: SEV_MARK[k] for k in SEV_ORDER}, "labels": SEV_LABEL}
outcome_series = {"colors": {"success": OK, "failure": SEV_MARK["critical"]},
                  "labels": {"success": "Thành công", "failure": "Thất bại"}}
HTTP_CLASSES = [("2xx thành công", "http.response.status_code:[200 TO 299]"),
                ("3xx chuyển hướng", "http.response.status_code:[300 TO 399]"),
                ("4xx lỗi phía client", "http.response.status_code:[400 TO 499]"),
                ("5xx lỗi máy chủ", "http.response.status_code:[500 TO 599]")]
http_series = {"colors": dict(zip([k for k, _ in HTTP_CLASSES], (OK, ACCENT, SEV_MARK["medium"], SEV_MARK["critical"])))}



def real(q=""):
    """Alert thật: loại alert chạy bóng (alert.shadow, rule đo thử), cùng quy ước với console (shadow=exclude) và KPI.
    An toàn trước khi mapping có alert.shadow: ES coi `NOT field:true` là đúng với mọi bản ghi."""
    return f"({q}) AND NOT alert.shadow:true" if q else "NOT alert.shadow:true"


def det(q=""):
    """Alert phát hiện để đếm tổng / top: loại health (sự cố nền tảng, ô riêng ở SOC KPI) và rba (alert cộng dồn rủi ro
    từ các alert khác — đếm chung là đếm hai lần; ô riêng "Alert RBA"). Alert dò ngược TI-002 (retrohunt) vẫn tính."""
    return real(f"({q}) AND NOT alert.source:(health OR rba)" if q else "NOT alert.source:(health OR rba)")


def kpi_alert(q=""):
    """Alert PHÁT HIỆN theo R62: rule / wazuh / ml, không bóng. Loại rba (cộng dồn rủi ro), health, retrohunt (TI-002)."""
    return real(f"({q}) AND alert.source:(rule OR wazuh OR ml)" if q else "alert.source:(rule OR wazuh OR ml)")


# Phiên đăng nhập: đăng nhập hệ thống (SSH, PAM, Windows logon 4624/4625 — event.category authentication)
# và đăng nhập form web (POST tới đường dẫn login — access log không có tên tài khoản, chỉ có IP và mã HTTP)
# Event nội bộ của nền tảng (console SOC: đăng nhập/đăng xuất giao diện; siem-xdr: kết quả phản ứng) không phải log hệ thống
INTERNAL = "event.module:(console OR siem-xdr)"
AUTH_ANY = "event.category:authentication"
AUTH = f"{AUTH_ANY} AND NOT {INTERNAL}"          # đăng nhập hệ thống thật (ssh, PAM, Windows)
CONSOLE_AUTH = f"{AUTH_ANY} AND event.module:console"
WEB_LOGIN = "event.category:web AND http.request.method:POST AND url.path:*login*"
PRIVILEGED = "user.name:(root OR Administrator OR admin)"

panels = [
    row("Tổng quan", 0),
    stat("Tổng event (không tính console/phản ứng)", EV, f"NOT {INTERNAL}", 0, 1, w=3),
    stat("Tổng alert", AL, det(), 3, 1, w=3),
    stat("Alert nghiêm trọng", AL, det("severity:critical"), 6, 1, w=3, spark=SEV_MARK["critical"]),
    stat("Alert mức cao", AL, det("severity:high"), 9, 1, w=3, spark=SEV_MARK["high"]),
    stat("Alert RBA (cộng dồn rủi ro)", AL, real("alert.source:rba"), 12, 1, w=3),
    stat("Alert chạy bóng", AL, "alert.shadow:true", 15, 1, w=3),
    all_time(stat("Case đang mở", CS, "status:(open OR in_progress OR contained)", 18, 1, w=3)),
    stat("Lệnh phản ứng XDR", AC, "", 21, 1, w=3),
    timeseries("Alert theo mức độ", AL, det(), "severity", 0, 5, **sev_series),
    # 11 loại event: quá 8 màu phân biệt được -> xếp hạng một màu thay cho cột chồng nhiều màu
    bars("Event theo loại (event.category)", EV, "", "event.category", 12, 5, w=12, size=12),
    row("Phát hiện (Detection)", 13),
    bars("Top rule kích hoạt", AL, det(), "rule.name", 0, 14, w=8, size=15),
    bars("MITRE ATT&CK tactic", AL, det(), "rule.mitre.tactic", 8, 14),
    bars("Top IP tấn công (từ alert)", AL, det(), "source.ip", 14, 14, w=5),
    bars("Host bị nhắm tới", AL, det(), "host.name", 19, 14, w=5),
    table("Alert mới nhất — bấm tên rule để mở trên console", AL, real(),
          ["@timestamp", "severity", "rule.id", "rule.name", "source.ip", "user.name", "host.name", "agent.id",
           "risk_score", "alert.status", "message", "alert.id"], 0, 22,
          overrides=[label_cells("alert.status", ALERT_CELLS), inspect("message"), width("@timestamp", 190),
                     width("severity", 125), width("rule.id", 115), width("agent.id", 85), width("risk_score", 85),
                     width("alert.status", 105), *console_link("alert", "alert.id", "rule.id", "rule.name")]),
    row("Telemetry", 32),
    timeseries("HTTP status code (Apache)", EV, "event.module:apache", HTTP_CLASSES, 0, 33, w=8, **http_series),
    bars("IP xác thực thất bại nhiều nhất", EV, f"{AUTH} AND event.outcome:failure", "source.ip",
         8, 33, w=8),
    bars("Nguồn dữ liệu (event.module)", EV, "", "event.module", 16, 33, w=8),
    bars("Top URL bị truy cập", EV, "event.category:web", "url.path", 0, 41, w=12, size=15),
    bars("Kết nối bị firewall chặn (IP nguồn)", EV, "event.action:deny", "source.ip", 12, 41, w=12),
    row("Phiên đăng nhập", 49),
    stat("Đăng nhập hệ thống thành công", EV, f"{AUTH} AND event.outcome:success", 0, 50, w=4),
    stat("Đăng nhập hệ thống thất bại", EV, f"{AUTH} AND event.outcome:failure", 4, 50, w=4),
    # tên tài khoản đặc quyền của máy (root, Administrator) hoặc admin; không tính tài khoản đăng nhập console SOC
    stat("Đặc quyền đăng nhập hệ thống được (root/Administrator/admin)", EV,
         f"{AUTH} AND event.outcome:success AND {PRIVILEGED}", 8, 50, w=4),
    stat("Đăng nhập form web bị từ chối", EV, f"{WEB_LOGIN} AND http.response.status_code:(401 OR 403)", 12, 50, w=4),
    stat("Đăng nhập console SOC thành công", EV, f"{CONSOLE_AUTH} AND event.outcome:success", 16, 50, w=4),
    stat("Đăng nhập console SOC thất bại", EV, f"{CONSOLE_AUTH} AND event.outcome:failure", 20, 50, w=4),
    timeseries("Đăng nhập hệ thống theo kết quả", EV, AUTH, "event.outcome", 0, 54, **outcome_series),
    bars("IP đăng nhập form web nhiều nhất", EV, WEB_LOGIN, "source.ip", 12, 54, w=12),
    bars("Tài khoản đăng nhập thất bại nhiều nhất", EV, f"{AUTH} AND event.outcome:failure", "user.name", 0, 62),
    bars("IP nguồn đăng nhập thành công", EV, f"{AUTH} AND event.outcome:success", "source.ip", 6, 62),
    bars("Đăng nhập theo máy", EV, AUTH, "host.name", 12, 62),
    bars("Hình thức đăng nhập", EV, AUTH, "event.action", 18, 62),
    table("Phiên đăng nhập gần đây", EV, f"{AUTH} OR ({WEB_LOGIN})",
          ["@timestamp", "event.outcome", "user.name", "source.ip", "host.name", "event.action", "auth.method",
           "winlog.logon.type", "url.path", "http.response.status_code", "message"], 0, 70,
          overrides=[label_cells("event.outcome", OUTCOME_CELLS), inspect("message")]),
    row("Phản ứng (XDR / SOAR)", 80),
    table("Lệnh phản ứng gần đây", AC, "", ["created_at", "agent_id", "type", "target", "source", "status", "expires_at", "output"],
          0, 81, h=9, time_field="created_at", overrides=[label_cells("status", ACTION_CELLS), inspect("output")]),
    all_time(table("Case đang mở — bấm tiêu đề để mở trên console", CS, "status:(open OR in_progress OR contained)",
                   ["created_at", "priority", "severity", "title", "entity", "alert_count", "assignee", "status", "id"],
                   0, 90, h=9, time_field="created_at",
                   overrides=[label_cells("status", CASE_CELLS), label_cells("priority", PRIO_CELLS),
                              *console_link("case", "id", "title")])),
]


def dashboard(uid, title, panels, refresh="30s", time_from="now-1h", templating=None):
    return {"uid": uid, "title": title, "tags": ["siem", "xdr", "soc"], "timezone": "browser", "schemaVersion": 39,
            "version": 1, "refresh": refresh, "time": {"from": time_from, "to": "now"}, "editable": True,
            "graphTooltip": 1,                    # rê chuột trên một biểu đồ thời gian: các biểu đồ khác cùng dóng mốc
            "panels": panels, "templating": {"list": templating or []}, "annotations": {"list": []}}


# ------------------------------------------------------------------ Điều tra thực thể
# Biến q (Lucene) do console đặt khi bấm "Điều tra" trên alert / agent / case: IP -> source.ip hoặc destination.ip,
# máy -> host.name, tài khoản -> user.name. Để trống (*) là xem toàn bộ.
Q = "(${q:raw})"
investigate = [
    row("Thực thể: ${q}", 0),
    stat("Event", EV, Q, 0, 1, w=6),
    stat("Alert", AL, real(Q), 6, 1, w=6),
    stat("Alert nghiêm trọng / cao", AL, real(f"{Q} AND severity:(critical OR high)"), 12, 1, w=6, spark=SEV_MARK["critical"]),
    stat("Đăng nhập thất bại (cả console)", EV, f"{Q} AND {AUTH_ANY} AND event.outcome:failure", 18, 1, w=6),
    bars("Event theo loại", EV, Q, "event.category", 0, 5, w=12, size=12),
    timeseries("Alert theo mức độ", AL, real(Q), "severity", 12, 5, **sev_series),
    bars("Hành động (event.action)", EV, Q, "event.action", 0, 13, w=6),
    bars("URL bị truy cập", EV, f"{Q} AND event.category:web", "url.path", 6, 13, w=6),
    bars("Tiến trình", EV, f"{Q} AND event.category:process", "process.name", 12, 13, w=6),
    bars("IP liên quan", EV, Q, "source.ip", 18, 13, w=6),
    table("Alert của thực thể — bấm tên rule để mở trên console", AL, real(Q),
          ["@timestamp", "severity", "rule.id", "rule.name", "source.ip", "user.name", "host.name", "alert.status",
           "alert.id"], 0, 21, h=9,
          overrides=[label_cells("alert.status", ALERT_CELLS), *console_link("alert", "alert.id", "rule.id", "rule.name")]),
    table("Event gần đây", EV, Q, ["@timestamp", "event.category", "event.action", "event.outcome", "source.ip",
                                   "user.name", "host.name", "process.name", "url.original", "message"], 0, 30, h=12,
          overrides=[label_cells("event.outcome", OUTCOME_CELLS), inspect("message")]),
]
q_var = {"type": "textbox", "name": "q", "label": "Bộ lọc (Lucene)", "query": "*",
         "current": {"text": "*", "value": "*"}, "options": [{"selected": True, "text": "*", "value": "*"}]}


# ------------------------------------------------------------------ Thư viện rule (tra cứu rule Wazuh + đề xuất AI)
# Dữ liệu: index siem-rules do manager đồng bộ (server/siem/rules_catalog.py). Danh mục không theo thời gian -> dashboard
# xem 20 năm; số alert 24 giờ / 7 ngày của từng rule đã tính sẵn trong danh mục.
# Từ Task 25 (P4) không còn rule YAML; cặp so sánh đề xuất <-> rule YAML (origin comparison) đã bỏ. Wazuh API (GET /rules) không
# liệt kê rules-dynamic/ (đo lại 08/11/2026, 4.14.8) nên danh mục không có rule AI / ngoại lệ: rule AI đếm theo đề xuất đã triển khai.
RU = {"type": "elasticsearch", "uid": "siem-rules"}
CATALOG = "origin:${origin:raw} AND mitre.tactic:$tactic AND tags:$tag AND fields:$field AND (${q:raw})"


def terms_var(name, label, field, query="origin:(wazuh_rule OR ai_proposal)", all_=True, size=300):
    return {"type": "query", "name": name, "label": label, "datasource": RU, "refresh": 1, "sort": 1,
            "query": json.dumps({"find": "terms", "field": field, "query": query, "size": size}, ensure_ascii=False),
            "includeAll": all_, "multi": all_, "allValue": "*" if all_ else None,
            "current": {"text": "All", "value": "$__all"} if all_ else {}}


rules_vars = [
    {"type": "custom", "name": "origin", "label": "Hiển thị",
     "query": "Tất cả : (wazuh_rule OR ai_proposal),Rule Wazuh : wazuh_rule,Đề xuất AI : ai_proposal",
     "current": {"text": "Tất cả", "value": "(wazuh_rule OR ai_proposal)"}},
    terms_var("tactic", "MITRE tactic", "mitre.tactic"),
    terms_var("tag", "Tag", "tags"),
    terms_var("field", "Trường log", "fields"),
    {"type": "textbox", "name": "q", "label": "Tìm (Lucene)", "query": "*", "current": {"text": "*", "value": "*"},
     "options": [{"selected": True, "text": "*", "value": "*"}]},
]
CATALOG_COLS = ["origin_label", "rule.id", "rule.name", "severity", "type", "mode_label", "mitre.tactic", "technique_text",
                "tags_text", "fields_text", "condition_text", "alerts.h24", "alerts.d7", "alerts.fp_rate30", "alerts.last",
                "proposal.status_label", "proposal.test", "proposal.fp", "proposal.alerts_per_day", "file",
                "proposal.id"]
# "Đang chạy" = rule Wazuh có mode:active (tạo alert thật)
LIB = "origin:wazuh_rule"
RUN = f"{LIB} AND mode:active"
rules_lib = [
    row("Tổng quan thư viện rule Wazuh", 0),
    stat("Rule đang chạy (tạo alert thật)", RU, RUN, 0, 1, w=4),
    stat("Rule chạy bóng (đo thử, không ra alert thật)", RU, f"{LIB} AND mode:shadow", 4, 1, w=4),
    stat("Rule Wazuh không cầu nối (không ra alert)", RU, f"{LIB} AND mode:nobridge", 8, 1, w=4),
    stat("Rule đã tắt", RU, f"{LIB} AND mode:off", 12, 1, w=4),
    stat("Rule Wazuh (tổng, mọi chế độ)", RU, "origin:wazuh_rule", 16, 1, w=4),
    stat("Rule im lặng 7 ngày (đang chạy)", RU, f"{RUN} AND alerts.d7:0", 20, 1, w=4),
    stat("Đề xuất AI đã triển khai (rules-dynamic/ai.xml)", RU, "origin:ai_proposal AND proposal.status:approved", 0, 5, w=8),
    stat("Đề xuất AI chờ duyệt", RU, "origin:ai_proposal AND proposal.status:pending", 8, 5, w=8),
    # cùng định nghĩa với dòng "không đạt kiểm định" của biểu đồ trạng thái bên dưới (status invalid)
    stat("Đề xuất không đạt kiểm định", RU, "origin:ai_proposal AND proposal.status:invalid", 16, 5, w=8),
    bars("Rule đang chạy theo MITRE tactic", RU, RUN, "mitre.tactic", 0, 9, w=8),
    bars("Đề xuất AI theo trạng thái", RU, "origin:ai_proposal", "proposal.status_label", 8, 9, w=8),
    bars("Rule kêu nhiều nhất (7 ngày): mã rule và tên", RU, f"{LIB} AND alerts.d7:>0", "rule.id", 16, 9, w=8,
         metric={"id": "1", "type": "sum", "field": "alerts.d7"}, name_field="rule.name"),
    row("Danh sách rule và đề xuất AI — lọc bằng các ô phía trên", 17),
    table("Rule và đề xuất AI — bấm mã rule xem cảnh báo của rule, bấm trạng thái đề xuất để mở trên console",
          RU, CATALOG, CATALOG_COLS, 0, 18, h=16, size=500, sort=("rule.id", False),
          rename={"origin_label": "Nguồn", "rule.id": "Mã", "rule.name": "Tên", "severity": "Mức độ", "type": "Loại",
                  "mitre.tactic": "Tactic", "technique_text": "Kỹ thuật", "tags_text": "Tag", "fields_text": "Trường log",
                  "condition_text": "Điều kiện", "alerts.h24": "Alert 24h", "alerts.d7": "Alert 7 ngày",
                  "mode_label": "Chế độ", "alerts.fp_rate30": "Báo nhầm 30 ngày",
                  "alerts.last": "Alert gần nhất", "proposal.status_label": "Trạng thái đề xuất",
                  "proposal.test": "Bắt mẫu kiểm tra", "proposal.fp": "Báo nhầm", "proposal.alerts_per_day": "Alert/ngày (ước tính)",
                  "file": "File"},
          overrides=[inspect("condition_text", 460), inspect("rule.name", 260), width("origin_label", 130),
                     inspect("fields_text", 200), hide("proposal.id"),
                     link_to("rule.id", "Xem cảnh báo của rule trên console", '/go/rule/${__data.fields["rule.id"]}'),
                     link_to("proposal.status_label", "Mở đề xuất trên console", '/go/proposal/${__data.fields["proposal.id"]}')]),
]

# ------------------------------------------------------------------ SOC KPI
# Dữ liệu: siem-kpi (manager/kpi.py tính mỗi 5 phút trên 30 ngày gần nhất) -> ô chỉ số lấy giá trị MỚI NHẤT, tô màu theo
# đích của kế hoạch SOC: xanh = đạt đích cuối giai đoạn 4, vàng = đạt đích giai đoạn 2, đỏ = chưa đạt.
KP = {"type": "elasticsearch", "uid": "siem-kpi"}
SR = {"type": "elasticsearch", "uid": "siem-sources"}
KPI_TARGETS = {   # = manager/kpi.py TARGETS: (đích GĐ2, đích GĐ4, càng thấp càng tốt?)
    "mttd_critical_s": (1800, 900, True), "mtta_p1_s": (1800, 900, True), "mttc_p1_s": (14400, 3600, True),
    "sla_pct": (85, 95, False), "fp_rate_pct": (50, 30, True), "alerts_per_analyst_shift": (60, 40, True),
    "enrichment_pct": (50, 80, False), "attack_coverage_pct": (50, 70, False), "source_health_pct": (95, 98, False),
    "hunts_month": (1, 2, False),
}


def kpi_steps(field):
    g2, g4, low = KPI_TARGETS[field]
    if low:
        return [{"color": OK, "value": None}, {"color": SEV_TEXT["medium"], "value": g4}, {"color": SEV_TEXT["critical"], "value": g2}]
    return [{"color": SEV_TEXT["critical"], "value": None}, {"color": SEV_TEXT["medium"], "value": g2}, {"color": OK, "value": g4}]


def kpi_stat(title, field, unit, x, y, w=4, desc=""):
    g2, g4, low = KPI_TARGETS[field]
    fmt = (lambda v: f"{v / 60:g} phút" if v < 3600 else f"{v / 3600:g} giờ") if unit == "s" else \
        (lambda v: f"{v:g}%" if unit == "percent" else f"{v:g}")
    cmp = "≤" if low else "≥"
    return {"id": pid(), "type": "stat", "title": title, "datasource": KP, "gridPos": {"x": x, "y": y, "w": w, "h": 4},
            "description": f"{desc} Đích: GĐ2 {cmp} {fmt(g2)}, GĐ4 {cmp} {fmt(g4)}.".strip(),
            "targets": [target(KP, "", metric={"id": "1", "type": "max", "field": field})],
            # con số mang màu trạng thái (đạt đích GĐ4 / GĐ2 / chưa đạt), không tô nền cả ô
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "colorMode": "value",
                        "graphMode": "area", "textMode": "value"},
            "fieldConfig": {"defaults": {"unit": unit, "decimals": 1, "noValue": "chưa đo",
                                         "thresholds": {"mode": "absolute", "steps": kpi_steps(field)},
                                         "color": {"mode": "thresholds"}}, "overrides": []}}


def kpi_trend(title, fields, unit, x, y, w=12, h=8):
    return {"id": pid(), "type": "timeseries", "title": title, "datasource": KP, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [target(KP, "", metric={"id": "1", "type": "max", "field": f}, ref=chr(65 + i), alias=label)
                        for i, (f, label) in enumerate(fields)],
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"drawStyle": "line", "lineWidth": 2, "spanNulls": True,
                                                                  "fillOpacity": 0, "showPoints": "auto"}},
                            "overrides": series_colors({label: SERIES[i] for i, (_, label) in enumerate(fields)})},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}}}


def avg_by(title, ds, query, field, by, unit, x, y, w=8, h=8, time_field="created_at"):
    """Trung bình `field` theo từng giá trị của `by` (giữ thứ tự, vd P1..P4): bảng có thanh như bars()."""
    p = bars(title, ds, query, by, x, y, w=w, h=h, metric={"id": "1", "type": "avg", "field": field}, sort_term=True)
    p["targets"][0]["timeField"] = time_field
    p["fieldConfig"]["defaults"].update(unit=unit, decimals=1)
    return p


SOURCE_CELLS = {"ok": ("Bình thường", ST_DONE), "deviation": ("Lệch nhịp", ST_WORK), "silent": ("Im lặng", ST_NEW)}
CLOSED = "alert.status:(closed OR false_positive)"
kpi_panels = [
    row("Chỉ số chính (30 ngày gần nhất) — xanh: đạt đích giai đoạn 4, vàng: đạt giai đoạn 2, đỏ: chưa đạt", 0),
    kpi_stat("MTTD alert critical", "mttd_critical_s", "s", 0, 1, desc="Từ event đầu tiên của chuỗi tấn công tới lúc sinh alert. Chỉ alert phát hiện (rule/wazuh/ml, không bóng); không tính RBA, health, dò ngược TI-002 (R62)."),
    kpi_stat("MTTA case P1", "mtta_p1_s", "s", 4, 1, desc="Từ lúc mở case tới khi có người nhận xử lý."),
    kpi_stat("MTTC case P1", "mttc_p1_s", "s", 8, 1, desc="Từ lúc mở case tới khi khoanh vùng xong (Đã ngăn chặn)."),
    kpi_stat("Tuân thủ SLA", "sla_pct", "percent", 12, 1, desc="% case xác nhận / khoanh vùng trong hạn của mức ưu tiên."),
    kpi_stat("Tỉ lệ báo nhầm", "fp_rate_pct", "percent", 16, 1, desc="Alert kết luận báo nhầm / alert đã đóng; chỉ alert phát hiện (R62)."),
    kpi_stat("Alert / analyst / ca", "alerts_per_analyst_shift", "short", 20, 1, desc="Tải công việc: alert phát hiện (R62) mỗi analyst mỗi ca."),
    kpi_stat("Làm giàu tự động", "enrichment_pct", "percent", 0, 5, w=6, desc="% alert phát hiện (R62) có ngữ cảnh tài sản."),
    kpi_stat("Độ phủ ATT&CK ưu tiên", "attack_coverage_pct", "percent", 6, 5, w=6,
             desc="% kỹ thuật trong threat_profile.yml có rule chạy chính thức đã kiểm thử."),
    kpi_stat("Sức khỏe nguồn log", "source_health_pct", "percent", 12, 5, w=6, desc="% nguồn đã onboard không im lặng."),
    kpi_stat("Hunt hoàn thành / tháng", "hunts_month", "short", 18, 5, w=6, desc="Số cuộc threat hunting hoàn thành."),
    row("Xu hướng", 9),
    kpi_trend("Thời gian phát hiện / nhận / khoanh vùng", [("mttd_critical_s", "MTTD critical"), ("mtta_p1_s", "MTTA P1"),
                                                         ("mttc_p1_s", "MTTC P1"), ("mtta.all", "MTTA mọi mức")], "s", 0, 10),
    kpi_trend("Tỉ lệ (%)", [("sla_pct", "Tuân thủ SLA"), ("fp_rate_pct", "Báo nhầm"), ("enrichment_pct", "Làm giàu"),
                            ("attack_coverage_pct", "Độ phủ ATT&CK"), ("source_health_pct", "Nguồn log khỏe")],
              "percent", 12, 10),
    row("Chất lượng cảnh báo phát hiện (rule/wazuh/ml, không bóng; theo khoảng thời gian của dashboard)", 18),
    bars("Kết luận khi đóng alert", AL, kpi_alert(CLOSED), "alert.verdict", 0, 19, w=6),
    bars("Rule báo nhầm nhiều nhất", AL, kpi_alert("alert.status:false_positive"), "rule.id", 6, 19, w=6),
    bars("Alert theo mức ưu tiên", AL, kpi_alert(), "priority", 12, 19, w=6, sort_term=True),
    avg_by("MTTA theo mức ưu tiên (case)", CS, "_exists_:metrics.tta_seconds", "metrics.tta_seconds", "priority", "s",
           18, 19, w=6),
    all_time(table("Case quá hạn xác nhận (chưa ai nhận) — bấm tiêu đề để mở trên console", CS,
                   "status:(open OR in_progress OR contained) AND NOT _exists_:acknowledged_at AND sla_due:<now",
                   ["sla_due", "priority", "severity", "title", "entity", "alert_count", "status", "id"], 0, 27, h=8,
                   time_field="created_at", sort=("sla_due", False),
                   overrides=[label_cells("status", CASE_CELLS), label_cells("priority", PRIO_CELLS),
                              *console_link("case", "id", "title")])),
    row("Nguồn log (soar/health.py, cập nhật mỗi phút)", 35),
    all_time(stat("Sự cố nền tảng đang mở", AL, "alert.source:health AND alert.status:(open OR acknowledged OR in_progress)",
                  0, 36, w=6, spark=SEV_MARK["critical"])),
    all_time(table("Trạng thái từng nguồn", SR, "", ["source", "host", "status", "last_event", "expected_per_hour",
                                                     "last_hour", "events_7d", "checked_at"], 6, 36, w=18, h=8,
                   time_field="checked_at", sort=("status", True),
                   rename={"source": "Nguồn", "host": "Máy", "status": "Trạng thái", "last_event": "Event gần nhất",
                           "expected_per_hour": "Trung bình / giờ", "last_hour": "1 giờ qua", "events_7d": "7 ngày",
                           "checked_at": "Kiểm tra lúc"},
                   overrides=[label_cells("status", SOURCE_CELLS)])),
    row("Độ phủ kỹ thuật ATT&CK ưu tiên (server/config/threat_profile.yml)", 44),
    all_time(table("Kỹ thuật ưu tiên và rule phát hiện", RU, "origin:coverage",
                   ["technique", "name", "covered_text", "rules_text", "shadow_text", "why"], 0, 45, h=10,
                   sort=("technique", False),
                   rename={"technique": "Kỹ thuật", "name": "Tên", "covered_text": "Có rule", "rules_text": "Rule chạy chính thức",
                           "shadow_text": "Đang chạy bóng", "why": "Vì sao ưu tiên"},
                   overrides=[label_cells("covered_text", {"có": ("Có", ST_DONE), "CHƯA CÓ": ("Chưa có", ST_NEW)})])),
]

for uid, title, body, extra in (
        ("siem-overview", "SIEM/XDR — Tổng quan SOC", panels, {}),
        ("siem-investigate", "SIEM/XDR — Điều tra thực thể", investigate, {"templating": [q_var], "time_from": "now-24h"}),
        ("siem-rules", "SIEM/XDR — Thư viện rule", rules_lib, {"templating": rules_vars, "time_from": "now-20y", "refresh": "1m"}),
        ("soc-kpi", "SIEM/XDR — SOC KPI", kpi_panels, {"time_from": "now-7d", "refresh": "5m"})):
    out = DIR / f"{uid}.json"
    out.write_text(json.dumps(dashboard(uid, title, body, **extra), ensure_ascii=False, indent=2),
                   encoding="utf-8", newline="\n")
    print(f"OK: {out} ({len(body)} panels)")
