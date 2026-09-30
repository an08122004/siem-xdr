"""Kiểm thử end-to-end trên stack đang chạy: tấn công thật vào máy web demo rồi kiểm tra cả chuỗi
event -> alert -> SOAR -> Wazuh agent -> kết quả, cùng đăng nhập / phân quyền console và Grafana.

    python tools/e2e_test.py                                  # admin còn mật khẩu tạm (secrets/console_admin_password)
    E2E_ADMIN_PASSWORD=<mật khẩu admin> python tools/e2e_test.py   # admin đã đặt mật khẩu riêng

Cần stack chạy đủ, kể cả --profile demo. Chạy từ thư mục siem-xdr. Tác dụng phụ trên hệ thống (đều được dọn):
chặn rồi gỡ chặn IP máy host trên demo-web, tạo rồi xóa file webshell thử (sinh alert + case thật, ghi rõ nguồn e2e),
tạo rồi xóa tài khoản `e2e-an`. Không chạy kiểm tra khóa tài khoản (5 lần sai sẽ khóa IP của bạn 15 phút).
"""
import base64
import os
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
BOOT = Path("secrets/console_admin_password").read_text().strip()
H = {"X-Requested-With": "siem-console", "Content-Type": "application/json"}
WEB = "http://127.0.0.1:8081"
START = datetime.now(timezone.utc).isoformat()
RESULTS = []


def check(scenario, name, ok, detail=""):
    RESULTS.append((scenario, name, ok))
    print(f"   {'✓' if ok else '✗'} {name}" + (f"  — {detail}" if detail else ""), flush=True)


class Console:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                              urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

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


def web(path, timeout=5):
    t0 = time.time()
    try:
        with urllib.request.urlopen(WEB + path, timeout=timeout) as r:
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




def drop_test_user():
    code = ("import sys; sys.path.insert(0, '/app'); from siem import store, settings\n"
            "es = store.connect(templates=False)\n"
            "try: es.delete(index=settings.IDX_USERS, id='e2e-an', refresh='wait_for')\n"
            "except Exception: pass")
    subprocess.run(["docker", "compose", "exec", "-T", "manager", "python", "-c", code], capture_output=True)


drop_test_user()
t_all = time.time()
print(f"Bắt đầu {datetime.now().strftime('%H:%M:%S')}\n")

# ----------------------------------------------------------------- 0. đăng nhập console
print("0. Chuẩn bị: đăng nhập console")
admin = Console()
OWN_ADMIN_PW = os.environ.get("E2E_ADMIN_PASSWORD")      # admin đã có mật khẩu riêng -> không đụng vào tài khoản admin
if OWN_ADMIN_PW:
    st, me = admin.call("POST", "/api/v1/auth/login", {"username": "admin", "password": OWN_ADMIN_PW})
    check("console", "admin đăng nhập", st == 200 and not me["must_change"])
else:
    st, me = admin.call("POST", "/api/v1/auth/login", {"username": "admin", "password": BOOT})
    check("console", "admin đăng nhập bằng mật khẩu tạm → bị buộc đổi", st == 200 and me["must_change"],
          "" if st == 200 else "admin đã có mật khẩu riêng? chạy lại với E2E_ADMIN_PASSWORD=...")
    TMP = "E2e-Tam-Thoi-Pw-2026"
    check("console", "admin đổi mật khẩu", admin.call("POST", "/api/v1/auth/password", {"current": BOOT, "new": TMP})[0] == 200)
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

# ----------------------------------------------------------------- 5. Grafana
print("\n5. Grafana")
pw = Path("secrets/grafana_admin_password").read_text().strip()
auth = {"Authorization": "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode(), "Content-Type": "application/json"}


def grafana(path, body=None):
    req = urllib.request.Request("http://localhost:3000" + path, headers=auth,
                                 data=json.dumps(body).encode() if body else None)
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


dash = grafana("/api/dashboards/uid/siem-overview")["dashboard"]
check("grafana", "dashboard SIEM/XDR tải được", len(dash["panels"]) == 35, f"{len(dash['panels'])} panel")
q = {"refId": "A", "datasource": {"type": "elasticsearch", "uid": "siem-events"},
     "query": "event.module:console AND event.category:authentication", "metrics": [{"id": "1", "type": "count"}],
     "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto"}}],
     "timeField": "@timestamp", "intervalMs": 60000, "maxDataPoints": 500}
frames = grafana("/api/ds/query", {"queries": [q], "from": "now-1h", "to": "now"})["results"]["A"].get("frames", [])
n = int(sum(sum(v for v in f["data"]["values"][1] if v) for f in frames if len(f["data"]["values"]) > 1))
check("grafana", "mục Phiên đăng nhập thấy lượt đăng nhập console vừa rồi", n > 0, f"{n} event trong 1 giờ")

# ----------------------------------------------------------------- dọn dẹp
print("\nDọn dẹp")
drop_test_user()
print("   đã xóa tài khoản test e2e-an")
if not OWN_ADMIN_PW:
    st, body = admin.call("PATCH", "/api/v1/users/admin", {"password": BOOT})
    print(f"   admin về lại mật khẩu tạm (bắt đổi khi đăng nhập): {'xong' if st == 200 and body['must_change'] else 'LỖI'}")

# ----------------------------------------------------------------- tổng kết
print(f"\nTỔNG KẾT ({time.time() - t_all:.0f} giây)")
names = {"console": "Đăng nhập / phân quyền console", "sqli": "SQL injection → chặn IP", "cmdi": "Command injection → kill",
         "fim": "Webshell → FIM → case", "grafana": "Grafana"}
for key, label in names.items():
    rs = [ok for s, _, ok in RESULTS if s == key]
    print(f"   {label:34s} {sum(rs)}/{len(rs)}")
total = sum(ok for *_, ok in RESULTS)
print(f"   {'Tất cả':34s} {total}/{len(RESULTS)}")
