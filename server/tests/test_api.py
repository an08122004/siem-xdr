"""Test Manager API + đăng nhập console bằng tài khoản riêng (ES, Kafka giả lập)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from siem import settings, store

H = {"X-Requested-With": "siem-console"}                                      # header chống CSRF mà console gửi kèm
HOST = "testserver.local"          # cookiejar gắn ".local" cho tên máy không có dấu chấm
ADMIN_TMP = "Tam-Thoi-Bootstrap-2026"      # mật khẩu mẫu KHÔNG chứa tên đăng nhập (chính sách chặn)
ADMIN_PW = "Quan-Tri-Vien-2026!"


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def time(self):
        return self.now


@pytest.fixture()
def env(monkeypatch):
    from siem.manager import api, auth

    class ES:
        pass
    users = auth.MemoryUserStore()
    audit, actions, clock = [], {}, Clock()
    monkeypatch.setattr(store, "connect", lambda: ES())
    monkeypatch.setattr(auth, "UserStore", lambda es: users)
    monkeypatch.setattr(auth, "sessions", auth.Sessions())
    monkeypatch.setattr(auth, "throttle", auth.Throttle())
    monkeypatch.setattr(auth, "audit", lambda action, outcome, user, ip, **kw: audit.append((action, outcome, user, kw)))
    monkeypatch.setattr(auth, "time", clock)
    monkeypatch.setattr(settings, "CONSOLE_ADMIN_PASSWORD", ADMIN_TMP)
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: actions.setdefault(
        f"a{len(actions)}", {"agent_id": aid, "type": t, "params": p, "status": "pending", **kw}))
    with TestClient(api.app, base_url="https://testserver") as c:     # cookie Secure chỉ gửi qua https
        c.users, c.audit, c.actions, c.clock = users, audit, actions, clock
        yield c


def login(c, username, password):
    return c.post("/api/v1/auth/login", json={"username": username, "password": password}, headers=H)


def activate(c, username, role):
    """admin tạo tài khoản (mật khẩu tạm) -> người dùng đăng nhập và đổi mật khẩu -> dùng được."""
    tmp, final = f"Tam-Thoi-Qwe-{len(username)}-2026", f"Rieng-Tu-Zx9-{len(username)}-2026"
    admin_login(c)
    assert c.post("/api/v1/users", json={"username": username, "role": role, "password": tmp}, headers=H).status_code == 200
    assert login(c, username, tmp).json()["must_change"] is True
    r = c.post("/api/v1/auth/password", json={"current": tmp, "new": final}, headers=H)
    assert r.status_code == 200 and r.json()["must_change"] is False
    return final


def admin_login(c):
    r = login(c, "admin", ADMIN_PW)
    if r.status_code != 200:
        assert login(c, "admin", ADMIN_TMP).json()["must_change"] is True
        assert c.post("/api/v1/auth/password", json={"current": ADMIN_TMP, "new": ADMIN_PW},
                      headers=H).status_code == 200


# ------------------------------------------------------------------ đăng nhập
def test_console_served_and_api_needs_login(env):
    r = env.get("/")
    assert r.status_code == 200 and "SIEM/XDR Console" in r.text and r.headers["x-frame-options"] == "DENY"
    assert "X-API-Key" not in r.text and "localStorage.setItem" not in r.text     # không còn API key trong trình duyệt
    assert env.get("/api/v1/alerts").status_code == 401
    assert env.get("/api/v1/alerts", headers={"X-API-Key": "whatever"}).status_code == 401


def test_bootstrap_admin_must_change_password(env):
    assert env.users.get("admin")["must_change"] and env.users.get("admin")["password_hash"].startswith("scrypt$")
    r = login(env, "admin", ADMIN_TMP)
    assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["must_change"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie
    assert env.get("/api/v1/stats").status_code == 403                          # chưa đổi mật khẩu tạm
    for bad, why in (("ngan", "tối thiểu"), ("admin-admin-admin", "tên đăng nhập"), (ADMIN_TMP, "khác mật khẩu cũ")):
        r = env.post("/api/v1/auth/password", json={"current": ADMIN_TMP, "new": bad}, headers=H)
        assert r.status_code == 400 and why in r.json()["detail"]
    assert env.post("/api/v1/auth/password", json={"current": "sai", "new": "Moi-Hoan-Toan-2026!"}, headers=H).status_code == 400
    assert env.post("/api/v1/auth/password", json={"current": ADMIN_TMP, "new": "Moi-Hoan-Toan-2026!"}, headers=H).status_code == 200
    assert env.get("/api/v1/stats").status_code == 200
    assert login(env, "admin", ADMIN_TMP).status_code == 401                     # mật khẩu tạm hết tác dụng
    assert ("login", "success", "admin", {"role": "admin"}) in env.audit


def test_wrong_password_and_lockout(env):
    assert login(env, "khongco", "gi-cung-duoc").json()["detail"] == login(env, "admin", "sai-mat-khau").json()["detail"]
    env.throttle_reset = None
    from siem.manager import auth
    auth.throttle.__init__()
    for _ in range(settings.CONSOLE_MAX_FAILURES):
        assert login(env, "admin", "sai-mat-khau").status_code == 401
    assert login(env, "admin", ADMIN_TMP).status_code == 429                     # đúng mật khẩu vẫn bị khóa
    assert env.audit[-1][3].get("reason") == "locked"
    env.clock.now += 16 * 60                                                     # hết 15 phút khóa
    assert login(env, "admin", ADMIN_TMP).status_code == 200


def test_csrf_header_required(env):
    r = env.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_TMP})
    assert r.status_code == 403                                                  # form từ trang lạ không có header
    admin_login(env)
    body = {"agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4"}}
    assert env.post("/api/v1/actions", json=body).status_code == 403
    assert env.post("/api/v1/actions", json=body, headers=H).status_code == 200


def test_session_idle_timeout_ignores_auto_refresh(env):
    admin_login(env)
    env.clock.now += 20 * 60
    assert env.get("/api/v1/stats", headers={"X-Auto-Refresh": "1"}).status_code == 200   # console tự làm mới
    env.clock.now += 11 * 60                                                               # 31 phút không thao tác
    assert env.get("/api/v1/stats", headers={"X-Auto-Refresh": "1"}).status_code == 401
    admin_login(env)
    for _ in range(3):                                                           # có thao tác -> phiên được gia hạn
        env.clock.now += 25 * 60
        assert env.get("/api/v1/stats").status_code == 200
    env.clock.now += 8 * 3600                                                    # tối đa 8 giờ dù vẫn thao tác
    assert env.get("/api/v1/stats").status_code == 401


def test_logout_invalidates_session(env):
    admin_login(env)
    token = env.cookies.get("siem_session")
    env.cookies.clear()
    env.cookies.set("siem_session", token, domain=HOST)
    assert env.get("/api/v1/stats").status_code == 200                          # đặt lại cookie bằng tay vẫn dùng được
    assert env.post("/api/v1/auth/logout").status_code == 200
    env.cookies.clear()
    env.cookies.set("siem_session", token, domain=HOST)                 # dùng lại token cũ
    assert env.get("/api/v1/stats").status_code == 401


# ------------------------------------------------------------------ phân quyền, người thực hiện
def test_roles_and_identity_from_session(env):
    activate(env, "lan", "lead")
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    r = env.post("/api/v1/actions", json={"agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4"}}, headers=H)
    assert r.status_code == 200 and r.json()["requested_by"] == "an"
    r = env.post("/api/v1/actions", json={"agent_id": "001", "type": "isolate_host", "params": {}}, headers=H)
    assert r.status_code == 403 and "lead" in r.json()["detail"]
    assert env.get("/api/v1/users").status_code == 403
    login(env, "lan", "Rieng-Tu-Zx9-3-2026")
    assert env.post("/api/v1/actions", json={"agent_id": "001", "type": "isolate_host", "params": {}},
                    headers=H).status_code == 200


def test_ai_approval_identity_comes_from_session(env, monkeypatch):
    from siem.manager import api
    monkeypatch.setattr(api.ai_deploy, "approve", lambda es, pid, analyst, *a, **kw: {"by": analyst})
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    r = env.post("/api/v1/ai/proposals/p1/approve", json={"analyst": "nguoi-khac"}, headers=H)
    assert r.status_code == 200 and r.json() == {"by": "an"}                     # tên tự khai bị bỏ qua


def test_user_admin_guards(env):
    admin_login(env)
    assert env.patch("/api/v1/users/admin", json={"disabled": True}, headers=H).status_code == 400   # không tự khóa
    assert env.post("/api/v1/users", json={"username": "An Hoa", "role": "analyst", "password": "x" * 12},
                    headers=H).status_code == 422
    assert env.post("/api/v1/users", json={"username": "an", "role": "god", "password": "Tam-Thoi-Qwe-2026"},
                    headers=H).status_code == 422
    pw = activate(env, "an", "analyst")
    admin_login(env)
    assert env.post("/api/v1/users", json={"username": "an", "role": "analyst", "password": "Tam-Thoi-Qwe-2027"},
                    headers=H).status_code == 409
    listed = env.get("/api/v1/users").json()
    assert {u["username"] for u in listed} == {"admin", "an"} and all("password_hash" not in u for u in listed)
    # đặt lại mật khẩu -> người đó phải đổi, phiên cũ bị hủy
    login(env, "an", pw)
    an_token = env.cookies.get("siem_session")
    admin_login(env)
    assert env.patch("/api/v1/users/an", json={"password": "Reset-Tam-2026-q"}, headers=H).json()["must_change"]
    env.cookies.clear()
    env.cookies.set("siem_session", an_token, domain=HOST)
    assert env.get("/api/v1/stats").status_code == 401
    admin_login(env)
    assert env.patch("/api/v1/users/an", json={"disabled": True}, headers=H).status_code == 200
    assert login(env, "an", "Reset-Tam-2026-q").status_code == 401                 # tài khoản bị khóa
    assert ("user_updated", "success", "admin", {"target": "an", "change": "khóa"}) in env.audit


# ------------------------------------------------------------------ case
def test_case_workflow(env):
    from siem.manager import api

    class CaseES:
        def __init__(self):
            self.doc = {"id": "c1", "status": "open", "assignee": None, "notes": [],
                        "tasks": [{"phase": "Ngăn chặn", "title": "Chặn IP", "approval": None, "done": False}]}
            self.seq = 1

        def get(self, index, id):
            return {"_source": dict(self.doc), "_seq_no": self.seq, "_primary_term": 1}

        def update(self, index, id, doc, if_seq_no=None, **_):
            if if_seq_no != self.seq:
                raise RuntimeError("conflict")
            self.doc.update(doc)
            self.seq += 1

    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    fake = CaseES()
    api._state["es"] = fake
    r = env.patch("/api/v1/cases/c1", json={"analyst": "gia-mao", "task_index": 0, "task_done": True}, headers=H)
    assert r.status_code == 200 and fake.doc["tasks"][0]["done_by"] == "an"
    # đóng case bắt buộc có kết luận
    assert env.patch("/api/v1/cases/c1", json={"status": "closed"}, headers=H).status_code == 400
    r = env.patch("/api/v1/cases/c1", json={"status": "closed", "note": "đã xử lý"}, headers=H)
    assert r.status_code == 200 and fake.doc["status"] == "closed" and fake.doc["closed_at"]
    assert [n["by"] for n in fake.doc["notes"]] == ["an", "an", "an"]
    assert env.patch("/api/v1/cases/c1", json={"status": "bậy"}, headers=H).status_code == 422
    env.post("/api/v1/auth/logout")
    assert env.patch("/api/v1/cases/c1", json={"note": "x"}, headers=H).status_code == 401


# ------------------------------------------------------------------ nhật ký đăng nhập thành event SIEM
def test_console_auth_events_normalized():
    from siem.pipeline.normalize import get, normalize

    def raw(**data):
        return {"timestamp": "2026-09-30T08:00:00+00:00", "agent_id": "soc-console", "hostname": "soc-console",
                "source": "console", "event_type": "console_auth", "data": data}
    doc = normalize(raw(action="login", outcome="failure", user="admin", ip="10.0.0.9", reason="bad_credentials"))
    assert get(doc, "event.category") == "authentication" and get(doc, "event.action") == "console_login"
    assert get(doc, "event.outcome") == "failure" and get(doc, "source.ip") == "10.0.0.9"
    assert get(doc, "user.name") == "admin" and get(doc, "host.name") == "soc-console"
    assert get(doc, "event.module") == "console" and get(doc, "event.reason") == "bad_credentials"
    doc = normalize(raw(action="user_created", outcome="success", user="admin", ip="10.0.0.9", target="an",
                        target_role="analyst"))
    assert get(doc, "event.category") == "iam" and get(doc, "user.target.name") == "an"
    assert get(doc, "user.roles") == "analyst"
