"""Kiểm thử end-to-end trên stack đang chạy: tấn công thật vào máy web demo rồi kiểm tra cả chuỗi
event -> alert -> SOAR -> Wazuh agent -> kết quả, cùng đăng nhập / phân quyền console và Grafana.

    python tools/e2e_test.py

Không dùng tài khoản `admin` thật: tự tạo tài khoản quản trị tạm `e2e-admin` (mật khẩu tạm, bị buộc đổi) thẳng
trong Elasticsearch qua container manager, và analyst `e2e-an` qua API.

Cần stack chạy đủ, kể cả --profile demo. Chạy từ thư mục siem-xdr. Tác dụng phụ trên hệ thống (đều được dọn):
chặn rồi gỡ chặn IP máy host trên demo-web, tạo rồi xóa file webshell thử (sinh alert + case thật, ghi rõ nguồn e2e),
tạo rồi xóa tài khoản `e2e-admin`, `e2e-an` (cả bên console lẫn Grafana). Không chạy kiểm tra khóa tài khoản (5 lần sai sẽ khóa IP của bạn 15 phút).
"""
import http.cookiejar
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
CTX = ssl.create_default_context()
CTX.check_hostname, CTX.verify_mode = False, ssl.CERT_NONE
ADMIN_TMP, ADMIN_PW = "Mat-Khau-Tam-Qp7-2026", "Quan-Tri-Tam-Zx9-2026"     # không chứa tên đăng nhập (chính sách)
H = {"X-Requested-With": "siem-console", "Content-Type": "application/json"}
WEB = "http://127.0.0.1:8081"
START = datetime.now(timezone.utc).isoformat()
RESULTS = []


def check(scenario, name, ok, detail=""):
    RESULTS.append((scenario, name, ok))
    print(f"   {'✓' if ok else '✗'} {name}" + (f"  — {detail}" if detail else ""), flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None                                      # trả nguyên 30x để kiểm tra Location


class Console:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                              urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                              NoRedirect())

    def raw(self, method, path, body=None, headers=None):
        """(status, headers, body bytes) — dùng cho Grafana sau manager."""
        req = urllib.request.Request("https://localhost:8000" + path, method=method, headers={**H, **(headers or {})},
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.op.open(req, timeout=30) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def grafana(self, path, body=None):
        st, _, b = self.raw("POST" if body is not None else "GET", "/grafana" + path, body)
        return st, (json.loads(b) if b and st < 500 else None)

    def call(self, method, path, body=None, headers=H):
        req = urllib.request.Request("https://localhost:8000" + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.op.open(req, timeout=20) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def get(self, path):
        return self.call("GET", path)[1]


def web(path, timeout=5, ua=None):
    t0 = time.time()
    req = urllib.request.Request(WEB + path, headers={"User-Agent": ua} if ua else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()                        # đọc hết nội dung: CGI gửi header ngay, thân trả về khi lệnh chạy xong
            return r.status, time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, time.time() - t0
    except Exception:  # noqa: BLE001 - bị chặn: không kết nối được
        return None, time.time() - t0


def wait(fn, timeout=90, step=2):
    end = time.time() + timeout
    while time.time() < end:
        if (v := fn()):
            return v
        time.sleep(step)
    return None


def sh(*cmd):
    return subprocess.run(["docker", "compose", *cmd], capture_output=True, text=True, encoding="utf-8").stdout


def alert(c, rule_prefix, pred=lambda a: True):
    return next((a for a in c.get("/api/v1/alerts?size=200") if a["@timestamp"] >= START
                 and a["rule"]["id"].startswith(rule_prefix) and pred(a)), None)


def action(c, typ, target=None, status="success"):
    return next((a for a in c.get("/api/v1/actions?size=200") if a["created_at"] >= START and a["type"] == typ
                 and (target is None or a["target"] == str(target)) and a["status"] == status), None)




def manager_py(code):
    return subprocess.run(["docker", "compose", "exec", "-T", "manager", "python", "-"], input=code,
                          capture_output=True, text=True, encoding="utf-8")


def drop_test_users():
    """Xóa tài khoản console e2e-* và user Grafana tự tạo tương ứng (manager là IP duy nhất Grafana tin header)."""
    manager_py("""
import httpx
from siem import store, settings
es = store.connect(templates=False)
g = httpx.Client(base_url=settings.GRAFANA_URL + '/grafana', headers={'X-WEBAUTH-USER': 'admin'})
for name in ('e2e-admin', 'e2e-an'):
    try:
        es.delete(index=settings.IDX_USERS, id=name, refresh='wait_for')
    except Exception:
        pass
    try:
        r = g.get('/api/users/lookup', params={'loginOrEmail': name})
        if r.status_code == 200:
            g.delete('/api/admin/users/%d' % r.json()['id'])
    except Exception:
        pass
""")


def create_test_admin():
    r = manager_py(f"""
from siem import store
from siem.manager import auth
auth.setup(store.connect(templates=False))
print(auth.users.create(auth.new_user('e2e-admin', 'admin', {ADMIN_TMP!r}, must_change=True)))
""")
    return r.stdout.strip().endswith("True")


drop_test_users()
t_all = time.time()
print(f"Bắt đầu {datetime.now().strftime('%H:%M:%S')}\n")

# ----------------------------------------------------------------- 0. đăng nhập console
print("0. Chuẩn bị: đăng nhập console")
admin = Console()
check("console", "tạo tài khoản quản trị tạm e2e-admin", create_test_admin())
st, me = admin.call("POST", "/api/v1/auth/login", {"username": "e2e-admin", "password": ADMIN_TMP})
check("console", "đăng nhập bằng mật khẩu tạm → bị buộc đổi", st == 200 and me["must_change"], str(st))
check("console", "chưa đổi mật khẩu → API từ chối (403)", admin.call("GET", "/api/v1/stats")[0] == 403)
check("console", "đổi mật khẩu", admin.call("POST", "/api/v1/auth/password", {"current": ADMIN_TMP, "new": ADMIN_PW})[0] == 200)
admin.call("POST", "/api/v1/users", {"username": "e2e-an", "role": "analyst", "password": "Tam-Thoi-Qwe-2026"})
an = Console()
an.call("POST", "/api/v1/auth/login", {"username": "e2e-an", "password": "Tam-Thoi-Qwe-2026"})
check("console", "analyst e2e-an được tạo và đổi mật khẩu",
      an.call("POST", "/api/v1/auth/password", {"current": "Tam-Thoi-Qwe-2026", "new": "Rieng-Tu-Zx9-2026"})[0] == 200)
agents = admin.get("/api/v1/agents")
check("console", "Wazuh agent demo-web online", any(a["hostname"] == "demo-web" and a["status"] == "online" for a in agents),
      ", ".join(f"{a['agent_id']} {a['hostname']} {a['status']}" for a in agents))

# ----------------------------------------------------------------- 1. SQLi
print("\n1. Tấn công SQL injection vào web demo")
check("sqli", "truy cập bình thường", web("/")[0] == 200)
t0 = time.time()
web("/products.html?id=1%20union%20select%20username,password%20from%20users")
a = wait(lambda: alert(admin, "WEB-001"))
check("sqli", "alert WEB-001", bool(a), f"{a['rule']['name']}, nguồn {a.get('source', {}).get('ip')}, sau {time.time() - t0:.0f}s" if a else "")
b = wait(lambda: action(admin, "block_ip"))
check("sqli", "SOAR chặn IP qua Wazuh, agent báo success", bool(b), f"{b['target']}: {b['output']}, sau {time.time() - t0:.0f}s" if b else "")
check("sqli", "máy host không vào được web nữa", web("/", timeout=4)[0] is None)
if b:
    st, _ = an.call("POST", "/api/v1/actions", {"agent_id": b["agent_id"], "type": "unblock_ip", "params": {"ip": b["target"]}})
    u = wait(lambda: action(admin, "unblock_ip", b["target"]))
    check("sqli", "analyst gỡ chặn từ console", st == 200 and bool(u), u["output"] if u else "")
    check("sqli", "vào lại được web", bool(wait(lambda: web("/")[0] == 200, timeout=30)))

# ----------------------------------------------------------------- 2. command injection
print("\n2. Command injection qua /cgi-bin/ping.cgi (shell chạy 15 giây)")
t0 = time.time()
code, elapsed = web("/cgi-bin/ping.cgi?host=127.0.0.1%3Bsleep%2015", timeout=30)
a = wait(lambda: alert(admin, "LNX-002"))
check("cmdi", "alert LNX-002 (web server sinh shell)", bool(a),
      f"{a.get('process', {}).get('name')} pid {a.get('process', {}).get('pid')}" if a else "")
k = wait(lambda: action(admin, "kill_process"))
check("cmdi", "SOAR kill cả cây tiến trình, agent báo success", bool(k), k["output"] if k else "")
check("cmdi", "request bị cắt ngang trước 15 giây", elapsed < 14, f"trả về sau {elapsed:.1f}s")

# ----------------------------------------------------------------- 3. FIM
print("\n3. Tải webshell lên thư mục web (FIM)")
t0 = time.time()
sh("exec", "-T", "demo-web", "sh", "-c", "echo '<?php system($_GET[c]); ?>' > /usr/local/apache2/htdocs/e2e-shell.php")
a = wait(lambda: alert(admin, "WZH-100100", lambda x: "e2e-shell.php" in str(x.get("file", {}).get("path"))), timeout=120)
check("fim", "alert WZH-100100 (file mới trong thư mục web)", bool(a),
      f"{a['severity']}, MITRE {a['rule']['mitre']['technique']}, sau {time.time() - t0:.0f}s" if a else "")
if a:
    case = wait(lambda: next((c for c in admin.get("/api/v1/cases?size=100") if a["alert"]["id"] in (c.get("alert_ids") or [])), None))
    check("fim", "SOAR mở case theo PB-08", bool(case) and case["playbook"]["id"] == "PB-08",
          f"{case['playbook']['id']} {case['priority']}, {len(case['tasks'])} task" if case else "")
sh("exec", "-T", "demo-web", "rm", "-f", "/usr/local/apache2/htdocs/e2e-shell.php")
d = wait(lambda: alert(admin, "WZH-553"), timeout=120)
check("fim", "xóa webshell → alert WZH-553 (file bị xóa)", bool(d), d["rule"]["name"] if d else "")

# ----------------------------------------------------------------- 4. phân quyền console
print("\n4. Phân quyền và phiên đăng nhập console")
check("console", "không đăng nhập → 401", Console().call("GET", "/api/v1/stats")[0] == 401)
st, body = an.call("POST", "/api/v1/actions", {"agent_id": "001", "type": "isolate_host", "params": {}})
check("console", "analyst cô lập máy → 403", st == 403, body["detail"])
check("console", "analyst quản lý tài khoản → 403", an.call("GET", "/api/v1/users")[0] == 403)
check("console", "thiếu header chống CSRF → 403",
      an.call("POST", "/api/v1/actions", {"agent_id": "001", "type": "block_ip", "params": {"ip": "198.51.100.9"}},
              headers={"Content-Type": "application/json"})[0] == 403)
an.call("POST", "/api/v1/auth/logout")
check("console", "sau đăng xuất → 401", an.call("GET", "/api/v1/stats")[0] == 401)

# ----------------------------------------------------------------- 5. Grafana (sau manager, dùng chung phiên console)
print("\n5. Grafana qua https://localhost:8000/grafana/ (dùng chung phiên console)")
NAV = {"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}
try:
    urllib.request.urlopen("http://localhost:3000/", timeout=3)
    check("grafana", "cổng 3000 không còn mở ra ngoài", False, "vẫn truy cập thẳng được Grafana")
except urllib.error.HTTPError as e:
    check("grafana", "cổng 3000 không còn mở ra ngoài", False, f"vẫn trả HTTP {e.code}")
except OSError:
    check("grafana", "cổng 3000 không còn mở ra ngoài", True)
r = subprocess.run(["docker", "compose", "exec", "-T", "demo-web", "sh", "-c",
                    "curl -s -m 3 -o /dev/null -w '%{http_code}' -H 'X-WEBAUTH-USER: admin' "
                    "http://grafana:3000/grafana/api/user"], capture_output=True, text=True)
check("grafana", "máy web demo gọi thẳng Grafana kèm header giả → không kết nối được",
      r.stdout.strip() in ("", "000"), f"curl exit {r.returncode}")
anon = Console()
st, hd, _ = anon.raw("GET", "/grafana/d/siem-overview", headers=NAV)
check("grafana", "chưa đăng nhập → chuyển tới trang đăng nhập chung",
      st == 303 and hd["Location"].startswith("/login?next=%2Fgrafana"), f"{st} {hd.get('Location')}")
check("grafana", "chưa đăng nhập, gọi API → 401", anon.grafana("/api/ds/query", {})[0] == 401)

an = Console()
an.call("POST", "/api/v1/auth/login", {"username": "e2e-an", "password": "Rieng-Tu-Zx9-2026"})
st, _, b = an.raw("GET", "/grafana/api/user", headers={"X-WEBAUTH-USER": "admin", "X-WEBAUTH-ROLE": "Admin"})
u = json.loads(b) if st == 200 else {}
orgs = an.grafana("/api/user/orgs")[1] or [{"role": "?"}]
check("grafana", "analyst vào Grafana bằng phiên console, giả header admin vô tác dụng",
      u.get("login") == "e2e-an" and orgs[0]["role"] == "Viewer", f"{u.get('login')} / {orgs[0]['role']}")
st, d = an.grafana("/api/dashboards/uid/siem-overview")
check("grafana", "analyst (Viewer) xem được dashboard, không sửa được", st == 200 and not d["meta"]["canSave"],
      f"{len(d['dashboard']['panels'])} panel" if st == 200 else str(st))
if st == 200:
    st, _ = an.grafana("/api/dashboards/db", {"dashboard": {**d["dashboard"], "title": "e2e sửa thử"}, "overwrite": True})
    check("grafana", "analyst lưu dashboard → 403", st == 403, str(st))
st, hd, _ = an.raw("GET", "/grafana/logout", headers=NAV)
out = st == 302 and hd["Location"] == "/logout" and an.raw("GET", "/logout", headers=NAV)[0] == 303
check("grafana", "Sign out trong Grafana → đăng xuất luôn phiên console",
      out and an.call("GET", "/api/v1/stats")[0] == 401, f"{st} {hd.get('Location')}")

st, orgs = admin.grafana("/api/user/orgs")
check("grafana", "quản trị console (e2e-admin) → Admin trong Grafana", st == 200 and orgs[0]["role"] == "Admin")
st, d = admin.grafana("/api/dashboards/uid/siem-overview")
check("grafana", "dashboard SIEM/XDR tải được", st == 200 and len(d["dashboard"]["panels"]) == 36,
      f"{len(d['dashboard']['panels'])} panel" if st == 200 else str(st))
q = {"refId": "A", "datasource": {"type": "elasticsearch", "uid": "siem-events"},
     "query": "event.module:console AND event.category:authentication", "metrics": [{"id": "1", "type": "count"}],
     "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto"}}],
     "timeField": "@timestamp", "intervalMs": 60000, "maxDataPoints": 500}
st, res = admin.grafana("/api/ds/query", {"queries": [q], "from": "now-1h", "to": "now"})
frames = res["results"]["A"].get("frames", []) if st == 200 else []
n = int(sum(sum(v for v in f["data"]["values"][1] if v) for f in frames if len(f["data"]["values"]) > 1))
check("grafana", "mục Phiên đăng nhập thấy lượt đăng nhập console vừa rồi", n > 0, f"{n} event trong 1 giờ")
st, d = admin.grafana("/api/dashboards/uid/siem-investigate")
check("grafana", "dashboard Điều tra thực thể (biến q) tải được", st == 200 and d["dashboard"]["templating"]["list"][0]["name"] == "q")
st, d = admin.grafana("/api/dashboards/uid/siem-rules")
check("grafana", "dashboard Thư viện rule tải được", st == 200 and len(d["dashboard"]["panels"]) == 15)


def catalog_count(query):
    cq = {"refId": "A", "datasource": {"type": "elasticsearch", "uid": "siem-rules"}, "query": query,
          "metrics": [{"id": "1", "type": "count"}], "timeField": "@timestamp", "intervalMs": 86400000,
          "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto"}}]}
    st, res = admin.grafana("/api/ds/query", {"queries": [cq], "from": "now-20y", "to": "now"})
    frames = res["results"]["A"].get("frames", []) if st == 200 else []
    return int(sum(sum(v for v in f["data"]["values"][1] if v) for f in frames if len(f["data"]["values"]) > 1))


n_files = sum(1 for f in Path("server/rules").glob("**/*.y*ml") if "exceptions" not in f.parts
              for line in f.read_text(encoding="utf-8").splitlines() if line.startswith("- id:"))
n_rules = catalog_count("origin:rule")
check("grafana", "Thư viện rule liệt kê đủ rule trong server/rules (Grafana đọc qua siem-rules)", n_rules == n_files,
      f"{n_rules}/{n_files} rule")
n_prop, n_cmp = catalog_count("origin:ai_proposal"), catalog_count("origin:comparison")
check("grafana", "đề xuất AI có trong thư viện, kèm cặp so sánh với rule hiện có", n_prop == 0 or n_cmp > 0,
      f"{n_prop} đề xuất, {n_cmp} cặp so sánh")

# ----------------------------------------------------------------- 6. hồi quy các lỗi đã sửa 3/10, 11/10
def count_events(query, want):
    """Số event khớp truy vấn Lucene trong 15 phút gần đây (qua datasource Grafana), chờ tới khi đủ `want`."""
    q["query"] = query
    n = 0
    for _ in range(30):
        st, res = admin.grafana("/api/ds/query", {"queries": [q], "from": "now-15m", "to": "now"})
        frames = res["results"]["A"].get("frames", []) if st == 200 else []
        n = int(sum(sum(v for v in f["data"]["values"][1] if v) for f in frames if len(f["data"]["values"]) > 1))
        if n >= want:
            break
        time.sleep(2)
    return n


print("\n6. Hồi quy")
burst = f"e2e{int(time.time())}"
for i in range(10):                                   # 10 request trong cùng 1 giây -> cùng id Wazuh
    web(f"/index.html?{burst}={i}")
n = count_events(f"event.module:apache AND url.original:*{burst}*", 10)
check("regress", "10 request trong cùng giây -> đủ 10 event trong ES (không ghi đè vì trùng id Wazuh)", n == 10, f"{n}/10")
pid1 = subprocess.run(["docker", "compose", "exec", "-T", "demo-web", "cat", "/proc/1/comm"], capture_output=True, text=True)
check("regress", "PID 1 của demo-web không phải httpd (tiến trình mồ côi không bị coi là web server sinh shell)",
      pid1.stdout.strip() not in ("", "httpd"), pid1.stdout.strip())
# User-Agent giả dòng telemetry của agent (sửa 11/10): trước đây thành event tiến trình -> LNX-002 -> SOAR tự kill PID
# do kẻ tấn công chọn, hoặc thành "kết quả lệnh" và thoát mọi rule web. URL vô hại nên không có lệnh chặn IP nào.
forged = f"e2ef{int(time.time())}"
web(f"/index.html?{forged}=proc", ua="x siem-proc: pid=999999 ppid=1 uid=33 name=sh parent=httpd exe=/bin/sh cmd=sh")
web(f"/index.html?{forged}=xdr", ua="x siem-xdr: action=deadbeef type=block_ip target=1.1.1.1 status=success detail=")
n = count_events(f"event.category:web AND event.action:http_request AND url.original:*{forged}*", 2)
check("regress", "User-Agent giả dòng telemetry của agent -> vẫn là request web", n == 2, f"{n}/2")
fake_kill = [a for a in admin.get("/api/v1/actions?size=200") if a["created_at"] >= START
             and a["type"] == "kill_process" and a["target"] == "999999"]
fake_alert = alert(admin, "LNX-002", lambda a: str((a.get("process") or {}).get("pid")) == "999999")
check("regress", "... không sinh LNX-002 / lệnh kill cho PID giả", not fake_kill and not fake_alert,
      f"{len(fake_kill)} lệnh kill, alert {'có' if fake_alert else 'không'}")

# ----------------------------------------------------------------- dọn dẹp
print("\nDọn dẹp")
admin.call("POST", "/api/v1/auth/logout")
drop_test_users()
print("   đã xóa tài khoản test e2e-admin, e2e-an (console + Grafana)")

# ----------------------------------------------------------------- tổng kết
print(f"\nTỔNG KẾT ({time.time() - t_all:.0f} giây)")
names = {"console": "Đăng nhập / phân quyền console", "sqli": "SQL injection → chặn IP", "cmdi": "Command injection → kill",
         "fim": "Webshell → FIM → case", "grafana": "Grafana", "regress": "Hồi quy lỗi đã sửa"}
for key, label in names.items():
    rs = [ok for s, _, ok in RESULTS if s == key]
    print(f"   {label:34s} {sum(rs)}/{len(rs)}")
total = sum(ok for *_, ok in RESULTS)
print(f"   {'Tất cả':34s} {total}/{len(RESULTS)}")
