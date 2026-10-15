"""Test Manager API + đăng nhập console bằng tài khoản riêng (ES, Kafka giả lập)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from siem import settings, store

H = {"X-Requested-With": "siem-console"}                                      # header chống CSRF mà console gửi kèm
HOST = "testserver.local"          # cookiejar gắn ".local" cho tên máy không có dấu chấm
ADMIN_TMP = "Tam-Thoi-Bootstrap-2026"      # mật khẩu mẫu KHÔNG chứa tên đăng nhập (chính sách chặn)
ADMIN_PW = "Quan-Tri-Vien-2026!"


class SessionDB:
    """Thay index console-sessions: phiên sống qua lần 'manager khởi động lại' (Sessions mới, cùng kho)."""

    def __init__(self):
        self.d = {}

    def save(self, s):
        self.d[s.key] = dict(vars(s))

    def load(self, key):
        from siem.manager import auth
        return auth.Session(**self.d[key]) if key in self.d else None

    def delete(self, key):
        self.d.pop(key, None)

    def delete_user(self, username, keep=None):
        self.d = {k: v for k, v in self.d.items() if v["username"] != username or k == keep}

    def all(self):
        from siem.manager import auth
        return [auth.Session(**v) for v in self.d.values()]

    def purge(self, active_before, created_before):
        self.d = {k: v for k, v in self.d.items() if v["last_active"] >= active_before and v["created"] >= created_before}


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
    users, sessiondb = auth.MemoryUserStore(), SessionDB()
    audit, actions, clock = [], {}, Clock()
    monkeypatch.setattr(store, "connect", lambda: ES())
    monkeypatch.setattr(auth, "UserStore", lambda es: users)
    monkeypatch.setattr(auth, "SessionStore", lambda es: sessiondb)
    monkeypatch.setattr(auth, "sessions", auth.Sessions())
    monkeypatch.setattr(auth, "throttle", auth.Throttle())
    monkeypatch.setattr(auth, "audit", lambda action, outcome, user, ip, **kw: audit.append((action, outcome, user, kw)))
    monkeypatch.setattr(auth, "time", clock)
    monkeypatch.setattr(settings, "CONSOLE_ADMIN_PASSWORD", ADMIN_TMP)
    monkeypatch.setattr(settings, "GRAFANA_URL", "")                      # không gán quyền Grafana lúc khởi động
    monkeypatch.setattr(settings, "RULES_CATALOG_SECONDS", 0)             # không đồng bộ danh mục rule nền
    monkeypatch.setattr(settings, "KPI_SECONDS", 0)                       # không tính KPI nền
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: actions.setdefault(
        f"a{len(actions)}", {"agent_id": aid, "type": t, "params": p, "status": "pending", **kw}))
    monkeypatch.setattr(store, "list_agents", lambda es: [{"agent_id": "001", "hostname": "demo-web", "status": "online"}])
    with TestClient(api.app, base_url="https://testserver") as c:     # cookie Secure chỉ gửi qua https
        c.users, c.audit, c.actions, c.clock, c.sessiondb = users, audit, actions, clock, sessiondb
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
def test_console_redirects_to_login_page_and_api_needs_login(env):
    r = env.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=%2F"          # chưa đăng nhập
    r = env.get("/login")
    assert r.status_code == 200 and "Đăng nhập" in r.text and r.headers["x-frame-options"] == "SAMEORIGIN"
    assert "localStorage" not in r.text                                                # không lưu gì phía trình duyệt
    assert env.get("/api/v1/auth/policy").json() == {"idle_minutes": 30, "session_hours": 8, "max_failures": 5,
                                                     "lock_minutes": 15, "min_password": 12, "min_distinct": 6}
    assert env.get("/api/v1/alerts").status_code == 401
    assert env.get("/api/v1/alerts", headers={"X-API-Key": "whatever"}).status_code == 401
    assert [env.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")] == [404] * 3   # không lộ sơ đồ API
    login(env, "admin", ADMIN_TMP)
    r = env.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?change=1&next=%2F"   # mật khẩu tạm: đổi trước
    admin_login(env)
    r = env.get("/", follow_redirects=False)
    assert r.status_code == 200 and "Trung tâm giám sát an ninh" in r.text and "X-API-Key" not in r.text


def test_logout_link_used_by_grafana(env):
    admin_login(env)
    r = env.get("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?reason=logged_out"
    assert env.get("/api/v1/stats").status_code == 401
    assert env.audit[-1][:3] == ("logout", "success", "admin")


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


def test_sessions_survive_manager_restart(env, monkeypatch):
    from siem.manager import auth
    restart = lambda: monkeypatch.setattr(auth, "sessions", auth.Sessions(env.sessiondb))   # noqa: E731 - bộ nhớ trống
    admin_login(env)                                          # gồm đổi mật khẩu tạm: must_change=False phải được lưu
    restart()
    me = env.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["username"] == "admin" and me.json()["must_change"] is False
    assert env.get("/api/v1/alerts").status_code != 401      # dùng tiếp được, không bị đẩy ra trang đăng nhập
    env.clock.now += 31 * 60                                  # quá thời gian không thao tác
    restart()
    assert env.get("/api/v1/auth/me").status_code == 401 and not env.sessiondb.d   # hết hạn vẫn là hết hạn
    admin_login(env)
    assert env.post("/api/v1/auth/logout", headers=H).status_code == 200
    restart()
    assert env.get("/api/v1/auth/me").status_code == 401     # đã đăng xuất thì không sống lại sau khởi động lại


def test_dropped_sessions_stay_dropped_after_restart():
    from siem.manager import auth
    db = SessionDB()
    before = auth.Sessions(db)
    ta, a = before.create({"username": "an", "role": "analyst"}, "10.0.0.1")
    tb, _ = before.create({"username": "an", "role": "analyst"}, "10.0.0.2")
    tc, _ = before.create({"username": "ld", "role": "lead"}, "10.0.0.3")
    before.drop_user("an", keep=a)                            # vd "an" đổi mật khẩu ở phiên a
    after = auth.Sessions(db)                                 # manager khởi động lại
    assert after.get(ta) and after.get(tb) is None and after.get(tc)


def test_abandoned_sessions_and_failure_counters_are_pruned(env, monkeypatch):
    from siem.manager import auth
    for _ in range(3):
        login(env, "admin", ADMIN_TMP)                       # 3 phiên, không đăng xuất
    assert len(auth.sessions) == 3
    env.clock.now += 31 * 60                                  # bỏ quên quá thời gian không thao tác
    login(env, "admin", ADMIN_TMP)
    assert len(auth.sessions) == 1                            # phiên mới tạo kéo theo dọn phiên hết hạn
    monkeypatch.setattr(auth.Throttle, "MAX_KEYS", 50)
    t = auth.Throttle()
    for i in range(60):
        t.failure(f"user:rand{i}")
    env.clock.now += 16 * 60
    t.failure("user:late")
    assert len(t.failures) <= 2                               # bản ghi cũ hơn cửa sổ 15 phút đã bị dọn


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
    assert r.status_code == 403 and "contain" in r.json()["detail"]
    assert env.get("/api/v1/users").status_code == 403
    login(env, "lan", "Rieng-Tu-Zx9-3-2026")
    assert env.post("/api/v1/actions", json={"agent_id": "001", "type": "isolate_host", "params": {}},
                    headers=H).status_code == 200


def test_new_soc_roles_have_capabilities_not_a_ladder(env):
    """Vai trò theo cơ cấu SOC: quyền theo năng lực. Detection Engineer duyệt rule nhưng không xử lý cảnh báo / chặn IP;
    hunter và manager cô lập được máy; chỉ admin quản lý tài khoản."""
    from siem.manager import api
    body = {"agent_id": "001", "type": "isolate_host", "params": {}}
    block = {"agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4"}}
    expect = {"hunter": (200, 200, 403), "manager": (200, 200, 403), "detection": (403, 403, 403)}
    for role, (iso, blk, users) in expect.items():
        pw = activate(env, f"u-{role}", role)
        login(env, f"u-{role}", pw)
        me = env.get("/api/v1/auth/me").json()
        assert me["role"] == role and me["permissions"] == sorted(api.auth.PERMISSIONS[role]), role
        assert env.post("/api/v1/actions", json=body, headers=H).status_code == iso, role
        assert env.post("/api/v1/actions", json=block, headers=H).status_code == blk, role
        assert env.get("/api/v1/users").status_code == users, role
    roles = env.get("/api/v1/auth/roles").json()
    assert [r["role"] for r in roles] == ["analyst", "lead", "hunter", "detection", "manager", "admin"]
    assert env.post("/api/v1/users", json={"username": "x-y", "role": "god", "password": "Tam-Thoi-Qwe-2026"},
                    headers=H).status_code in (403, 422)


def test_ai_approval_identity_comes_from_session(env, monkeypatch):
    """Duyệt rule AI là việc của Detection Engineer (quyền rules): analyst xử lý cảnh báo không tự duyệt rule mình dùng
    (trước 13/10/2026 analyst duyệt được)."""
    from siem.manager import api
    monkeypatch.setattr(api.ai_deploy, "approve", lambda es, pid, analyst, *a, **kw: {"by": analyst})
    monkeypatch.setattr(api, "refresh_catalog", lambda: None)
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    assert env.post("/api/v1/ai/proposals/p1/approve", json={}, headers=H).status_code == 403
    assert env.post("/api/v1/ai/run", json={}, headers=H).status_code == 403
    pw = activate(env, "de", "detection")
    login(env, "de", pw)
    r = env.post("/api/v1/ai/proposals/p1/approve", json={"analyst": "nguoi-khac"}, headers=H)
    assert r.status_code == 200 and r.json() == {"by": "de"}                     # tên tự khai bị bỏ qua


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
    assert fake.doc["acknowledged_at"] and fake.doc["acknowledged_by"] == "an"           # thao tác đầu tiên = xác nhận
    # đóng case bắt buộc có ghi chú và kết luận
    assert env.patch("/api/v1/cases/c1", json={"status": "closed"}, headers=H).status_code == 400
    r = env.patch("/api/v1/cases/c1", json={"status": "closed", "note": "đã xử lý"}, headers=H)
    assert r.status_code == 400 and "kết luận" in r.json()["detail"]
    r = env.patch("/api/v1/cases/c1", json={"status": "closed", "note": "đã xử lý", "verdict": "true_positive"}, headers=H)
    assert r.status_code == 200 and fake.doc["status"] == "closed" and fake.doc["closed_at"]
    assert fake.doc["verdict"] == "true_positive" and fake.doc["contained_at"] == fake.doc["closed_at"]
    assert [n["by"] for n in fake.doc["notes"]] == ["an", "an", "an"]
    assert env.patch("/api/v1/cases/c1", json={"status": "bậy"}, headers=H).status_code == 422
    env.post("/api/v1/auth/logout")
    assert env.patch("/api/v1/cases/c1", json={"note": "x"}, headers=H).status_code == 401


def test_case_tasks_needing_approval_require_role(env, monkeypatch):
    """Task "cần Trưởng nhóm IR duyệt" (vd cô lập máy): trước đây analyst L1 vẫn đánh dấu được, nhãn chỉ để hiển thị."""
    from siem.manager import api
    monkeypatch.setattr(store, "search", lambda *a, **kw: [])
    pw_an, pw_ld = activate(env, "an", "analyst"), activate(env, "ld", "lead")
    tasks = [{"phase": "Ngăn chặn", "title": title, "approval": appr, "done": False} for title, appr in (
        ("Chặn IP", None), ("Chặn trên firewall biên", "Analyst L1"), ("Cô lập máy", "Trưởng nhóm IR"),
        ("Cài lại máy", "Trưởng nhóm IR + chủ hệ thống"), ("Việc lạ", "Ban giám đốc"))]
    es = DocES({"c1": {"id": "c1", "status": "open", "notes": [], "tasks": tasks}})
    api._state["es"] = es
    tick = lambda i, done=True, note="": env.patch("/api/v1/cases/c1", headers=H, json={   # noqa: E731
        "task_index": i, "task_done": done, "note": note}).status_code
    login(env, "an", pw_an)
    assert [t["approval_permission"] for t in env.get("/api/v1/cases/c1").json()["tasks"]] == [
        None, "triage", "contain", "contain", "contain"]                           # nhãn lạ -> cần contain
    assert [tick(0), tick(1), tick(2), tick(4)] == [200, 200, 403, 403]
    login(env, "ld", pw_ld)
    assert tick(2) == 200 and es.docs["c1"]["tasks"][2]["done_by"] == "ld"
    assert "duyệt với vai trò lead" in es.docs["c1"]["notes"][-1]["text"]
    assert tick(3) == 400                                                           # chủ hệ thống: phải ghi ai đồng ý
    assert tick(3, note="chủ hệ thống A đồng ý qua điện thoại 10:30") == 200
    login(env, "an", pw_an)
    assert tick(2, done=False) == 403                                               # không bỏ được quyết định của lead


def test_soar_step_awaiting_approval_is_approved_or_declined(env, monkeypatch):
    """Bước SOAR `approval: true` (cô lập máy) trước đây hiện "chờ duyệt" mãi: giờ ghi ai duyệt (tạo đúng lệnh đó từ
    alert) hoặc ai từ chối và vì sao."""
    from siem.manager import api
    monkeypatch.setattr(store, "list_agents", lambda es: [{"agent_id": "001", "status": "online"}])
    monkeypatch.setattr(store, "create_action", lambda es, agent, typ, params, **kw: {
        "id": "act1", "type": typ, "created_at": "2026-10-11T10:00:00+00:00"})
    pw_an, pw_ld = activate(env, "an", "analyst"), activate(env, "ld", "lead")
    step = {"playbook": "Diệt tiến trình", "action": "isolate_host", "status": "awaiting_approval"}
    docs = {k: {"alert": {"id": k, "status": "open"}, "soar": {"results": [dict(step)]}} for k in ("a1", "a2")}
    api._state["es"] = DocES(docs)
    login(env, "ld", pw_ld)
    r = env.post("/api/v1/actions", headers=H, json={"agent_id": "001", "type": "isolate_host", "params": {}, "alert_id": "a1"})
    assert r.status_code == 200
    assert {k: docs["a1"]["soar"]["results"][0][k] for k in ("status", "approved_by", "action_id")} == {
        "status": "approved", "approved_by": "ld", "action_id": "act1"}
    assert docs["a1"]["alert"]["status"] == "open" and "duyệt bước SOAR" in docs["a1"]["alert"]["history"][-1]["text"]
    decline = lambda alert, reason: env.post(f"/api/v1/alerts/{alert}/soar/decline", headers=H, json={   # noqa: E731
        "action": "isolate_host", "reason": reason}).status_code
    login(env, "an", pw_an)
    assert decline("a2", "máy chủ production") == 403                              # cô lập: chỉ lead quyết định
    login(env, "ld", pw_ld)
    assert decline("a2", "x") == 400 and decline("khong-co", "máy chủ production") == 404
    assert decline("a2", "máy chủ production, chờ cửa sổ bảo trì") == 200
    res = docs["a2"]["soar"]["results"][0]
    assert res["status"] == "declined" and res["declined_by"] == "ld" and "bảo trì" in res["reason"]
    assert decline("a2", "lần nữa") == 409 and decline("a1", "đã duyệt rồi") == 409   # đã có quyết định


# ------------------------------------------------------------------ alert, lệnh phản ứng, liên kết từ Grafana
class DocES:
    """ES giả: get / update theo id, NotFoundError khi không có, kiểm tra seq_no như ES thật."""

    def __init__(self, docs):
        self.docs, self.seq = docs, {k: 1 for k in docs}

    def get(self, index, id):
        from elasticsearch import NotFoundError
        if id not in self.docs:
            raise NotFoundError("not found", meta=type("M", (), {"status": 404})(), body={})
        return {"_source": self.docs[id], "_seq_no": self.seq[id], "_primary_term": 1}

    def update(self, index, id, doc, if_seq_no=None, **_):
        for k, v in doc.items():
            self.docs[id][k] = (self.docs[id].get(k) or {}) | v if isinstance(v, dict) else v
        self.seq[id] += 1


def test_alert_filters_detail_and_history(env, monkeypatch):
    from siem.manager import api
    searches = []

    def search(es, index, query=None, size=100, sort=None):
        searches.append((index, query))
        return [{"_id": "c9", "id": "c9", "title": "SQLi — 1.2.3.4", "status": "open"}] if index == settings.IDX_CASES else []
    monkeypatch.setattr(store, "search", search)
    admin_login(env)
    env.get("/api/v1/alerts?status=open,in_progress&severity=critical&since=24h&q=203.0.113.9")
    flt = searches[-1][1]["bool"]["filter"]
    assert {"terms": {"alert.status": ["open", "in_progress"]}} in flt and {"terms": {"severity": ["critical"]}} in flt
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in flt
    assert {"term": {"source.ip": "203.0.113.9"}} in flt[-1]["bool"]["should"]      # tìm IP -> so khớp trường IP
    api._state["es"] = DocES({"a1": {"rule": {"id": "WEB-001"}, "alert": {"id": "a1", "status": "open"}}})
    assert env.get("/api/v1/alerts/khong-co").status_code == 404
    a = env.get("/api/v1/alerts/a1").json()
    assert a["_id"] == "a1" and a["cases"][0]["id"] == "c9" and a["actions"] == []
    assert env.patch("/api/v1/alerts/khong-co", json={"status": "closed"}, headers=H).status_code == 404
    r = env.patch("/api/v1/alerts/a1", json={"status": "false_positive", "note": "quét bảo mật nội bộ"}, headers=H)
    assert r.status_code == 200
    hist = api._state["es"].docs["a1"]["alert"]["history"]
    assert hist[0]["by"] == "admin" and "open -> false_positive" in hist[0]["text"] and "quét bảo mật" in hist[0]["text"]


def test_case_search_by_title_words_and_active_alert_count(env, monkeypatch):
    from siem.manager import api
    searches, counts = [], []
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: searches.append(query) or [])
    admin_login(env)
    env.get("/api/v1/cases?q=brute*")
    should = searches[-1]["bool"]["filter"][-1]["bool"]["should"]
    # title là keyword: phải tìm được theo chuỗi con, không phân biệt hoa thường; * do người dùng gõ là ký tự thường
    assert {"wildcard": {"title": {"value": "*brute\\**", "case_insensitive": True}}} in should

    class CountES:
        def count(self, index, query):
            counts.append((index, query))
            return {"count": 0}
    api._state["es"] = CountES()
    env.get("/api/v1/stats")
    # số trên menu "Cảnh báo" = danh sách "Đang mở" của console (gồm cả đã xác nhận), không tính alert chạy bóng
    assert (settings.IDX_ALERTS, {"bool": {"filter": [{"terms": {"alert.status": ["open", "acknowledged", "in_progress"]}}],
                                           "must_not": [{"term": {"alert.shadow": True}}]}}) in counts


def test_alert_close_requires_verdict_and_records_acknowledgement(env, monkeypatch):
    """Đóng alert phải chọn kết luận (đo tỉ lệ báo nhầm); lần đổi trạng thái đầu tiên = xác nhận (KPI MTTA); kết luận
    "báo nhầm" luôn đi cùng trạng thái false_positive (AI worker lấy nhãn theo trạng thái này)."""
    from siem.manager import api
    monkeypatch.setattr(store, "search", lambda *a, **kw: [])
    docs = {k: {"@timestamp": "2026-10-13T10:00:00+00:00", "alert": {"id": k, "status": "open"}} for k in ("a1", "a2")}
    docs["sh"] = {"@timestamp": "2026-10-13T10:00:00+00:00", "alert": {"id": "sh", "status": "open", "shadow": True}}
    api._state["es"] = DocES(docs)
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    patch = lambda k, **b: env.patch(f"/api/v1/alerts/{k}", json=b, headers=H)          # noqa: E731
    r = patch("a1", status="closed")
    assert r.status_code == 400 and "kết luận" in r.json()["detail"]
    assert patch("a1", status="closed", verdict="lung-tung").status_code == 422
    r = patch("a1", status="acknowledged")
    a1 = docs["a1"]["alert"]
    assert r.status_code == 200 and a1["acknowledged_by"] == "an" and docs["a1"]["metrics"]["tta_seconds"] > 0
    first_ack = a1["acknowledged_at"]
    r = patch("a1", status="closed", verdict="benign_true_positive", note="pentest đã báo trước")
    a1 = docs["a1"]["alert"]
    assert r.json()["verdict"] == "benign_true_positive" and a1["status"] == "closed" and a1["closed_by"] == "an"
    assert a1["acknowledged_at"] == first_ack                                       # xác nhận chỉ ghi lần đầu
    assert "hoạt động hợp lệ" in a1["history"][-1]["text"]
    r = patch("a2", status="closed", verdict="false_positive")                     # kết luận báo nhầm -> trạng thái
    assert r.json()["status"] == "false_positive" and docs["a2"]["alert"]["verdict"] == "false_positive"
    assert patch("a2", status="open").json()["verdict"] is None                     # mở lại -> bỏ kết luận
    # alert của rule chạy bóng: Detection Engineer ghi kết luận được (đo báo nhầm trước khi bật), alert thường thì không
    pw = activate(env, "de", "detection")
    login(env, "de", pw)
    assert patch("a1", status="open").status_code == 403
    assert patch("sh", status="false_positive").status_code == 200


def test_alert_list_hides_shadow_rules_and_filters_priority(env, monkeypatch):
    searches = []
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: searches.append(query) or [])
    admin_login(env)
    env.get("/api/v1/alerts?priority=P1,P2")
    q = searches[-1]["bool"]
    assert {"terms": {"priority": ["P1", "P2"]}} in q["filter"] and q["must_not"] == [{"term": {"alert.shadow": True}}]
    env.get("/api/v1/alerts?shadow=only")
    assert {"term": {"alert.shadow": True}} in searches[-1]["bool"]["filter"] and "must_not" not in searches[-1]["bool"]
    env.get("/api/v1/alerts?shadow=all")
    assert searches[-1] == {"bool": {"filter": []}}


def test_case_priority_change_sla_and_closing_alerts(env, monkeypatch):
    """Đổi ưu tiên cần quyền contain + lý do; nâng ưu tiên kéo hạn SLA về sớm hơn. Chuyển "Đã ngăn chặn" ghi mốc khoanh
    vùng (KPI MTTC) và đạt / trễ SLA. Đóng case đóng luôn các alert còn mở trong case, cùng kết luận."""
    from siem.manager import api
    monkeypatch.setattr(store, "search", lambda *a, **kw: [])
    created = store.now_iso()
    case = {"id": "c1", "status": "open", "notes": [], "tasks": [], "priority": "P3", "created_at": created,
            "alert_ids": ["a1", "a2"], **{k: v for k, v in api.prio.policy().dues(created, "P3").items()}}
    case["sla_due"], case["contain_due"] = case.pop("ack_due"), case.pop("contain_due")
    es = DocES({"c1": case})
    queries = []
    es.update_by_query = lambda **kw: queries.append(kw) or {"updated": 2}
    api._state["es"] = es
    pw_an, pw_ld = activate(env, "an", "analyst"), activate(env, "ld", "lead")
    patch = lambda **b: env.patch("/api/v1/cases/c1", json=b, headers=H)          # noqa: E731
    login(env, "an", pw_an)
    assert patch(priority="P1", note="máy chủ thanh toán").status_code == 403          # analyst không đổi ưu tiên
    login(env, "ld", pw_ld)
    assert patch(priority="P1").status_code == 400                                     # phải ghi lý do
    r = patch(priority="P1", note="máy chủ thanh toán bị ảnh hưởng")
    assert r.status_code == 200 and case["priority"] == "P1"
    assert case["sla"]["ack_due"] < api.prio.policy().dues(created, "P3")["ack_due"]   # hạn kéo về sớm hơn
    assert case["acknowledged_by"] == "ld" and case["sla"]["ack_met"] is True and case["metrics"]["tta_seconds"] >= 0
    r = patch(status="contained")
    assert case["contained_at"] and case["sla"]["contain_met"] is True and "ttc_seconds" in case["metrics"]
    r = patch(status="closed", verdict="duplicate", note="trùng case c0")
    assert r.status_code == 200 and r.json()["alerts_closed"] == 2 and case["verdict"] == "duplicate"
    q = queries[-1]
    assert q["query"]["bool"]["filter"][0] == {"terms": {"alert.id": ["a1", "a2"]}}
    assert q["script"]["params"]["status"] == "closed" and q["script"]["params"]["verdict"] == "duplicate"


def test_major_incident_declaration_by_soc_manager(env, monkeypatch):
    """Tuyên bố sự cố lớn: chỉ SOC Manager (quyền declare); case thành P1; lộ dữ liệu cá nhân -> hạn thông báo 72 giờ
    (Luật BVDLCN 91/2025, Điều 23) tính từ lúc hệ thống phát hiện; ghi nhận đã thông báo."""
    from siem.manager import api
    case = {"id": "c1", "status": "in_progress", "notes": [], "tasks": [], "priority": "P2",
            "created_at": "2026-10-13T08:00:00+00:00", "sla_due": "2026-10-13T08:30:00+00:00"}
    api._state["es"] = DocES({"c1": case})
    pw_ld, pw_mg = activate(env, "ld", "lead"), activate(env, "mg", "manager")
    post = lambda **b: env.post("/api/v1/cases/c1/incident", json=b, headers=H)   # noqa: E731
    login(env, "ld", pw_ld)
    assert post(action="declare", note="ransomware lan 3 máy").status_code == 403
    login(env, "mg", pw_mg)
    assert post(action="notified", note="đã gửi A05").status_code == 409            # chưa tuyên bố
    assert post(action="declare", note="").status_code == 400
    r = post(action="declare", personal_data=True, note="ransomware lan 3 máy, có CSDL khách hàng")
    assert r.status_code == 200 and case["priority"] == "P1" and case["incident"]["declared_by"] == "mg"
    assert case["incident"]["notify_due"] == "2026-10-16T08:00:00+00:00"
    assert post(action="declare", note="lần nữa").status_code == 409
    assert post(action="notified", note="đã thông báo A05 lúc 10:00").status_code == 200
    assert case["incident"]["notified_by"] == "mg" and "đã thông báo" in case["notes"][-1]["text"]


def test_manual_actions_are_validated(env):
    admin_login(env)

    def post(agent, typ, params):
        return env.post("/api/v1/actions", json={"agent_id": agent, "type": typ, "params": params}, headers=H)
    assert post("001", "block_ip", {"ip": "1.2.3.4; rm -rf /"}).status_code == 400
    assert post("001", "block_ip", {"ip": "127.0.0.1"}).status_code == 400            # loopback + whitelist mặc định
    assert post("001", "kill_process", {"pid": 1}).status_code == 400
    assert post("001", "kill_process", {"name": "a b"}).status_code == 400
    assert post("999", "block_ip", {"ip": "203.0.113.9"}).status_code == 400          # agent không tồn tại
    assert post("001", "format_disk", {}).status_code == 400
    assert post("001", "block_ip", {"ip": " 203.0.113.9 "}).json()["params"] == {"ip": "203.0.113.9"}
    assert post("001", "kill_process", {"pid": "4242"}).json()["params"] == {"pid": 4242}


def test_grafana_links_open_console_in_top_window(env):
    for path in ("/go/alert/a1b2", "/grafana/go/case/c-9"):         # /grafana/go không bị chuyển sang Grafana
        r = env.get(path)
        assert r.status_code == 200 and "window.top" in r.text
    assert '"/#/alerts/a1b2"' in env.get("/go/alert/a1b2").text
    assert '"/#/alerts?set=all&since=30d&q=WEB-001"' in env.get("/go/rule/WEB-001").text   # Thư viện rule -> cảnh báo của rule
    assert '"/#/ai/6410ad001f6c"' in env.get("/grafana/go/proposal/6410ad001f6c").text
    assert env.get("/go/user/x").status_code == 404
    assert env.get("/go/alert/%22%3Balert(1)").status_code == 404                    # id lạ không chèn được vào script
    r = env.get("/login")
    assert r.headers["x-frame-options"] == "SAMEORIGIN" and r.headers["content-security-policy"] == "frame-ancestors 'self'"


# ------------------------------------------------------------------ tự đăng ký, phiên và nhật ký cho admin
REG = {"username": "nv.an", "password": "Mat-Khau-Rieng-77", "full_name": "  Nguyễn   Văn An ", "birth_date": "2000-05-17",
       "hometown": "Nghệ An", "phone": "0912345678", "position": "Chuyên viên phân tích L1"}


def test_register_needs_admin_approval(env):
    assert env.post("/api/v1/auth/register", json=REG).status_code == 403                       # thiếu header CSRF
    r = env.post("/api/v1/auth/register", json=REG, headers=H)
    assert r.status_code == 200 and r.json()["pending"] is True
    assert env.post("/api/v1/auth/register", json=REG, headers=H).status_code == 409            # trùng tên
    for bad, msg in (({"birth_date": "2020-01-01"}, "ngày sinh"), ({"full_name": "   "}, "họ và tên"),
                     ({"password": "nv.khac-mat-khau"}, "tên đăng nhập")):
        r = env.post("/api/v1/auth/register", json={**REG, "username": "nv.khac", **bad}, headers=H)
        assert r.status_code == 400 and msg in r.json()["detail"], bad
    assert env.post("/api/v1/auth/register", json={**REG, "username": "nv.khac", "phone": "12345"}, headers=H).status_code == 422
    r = login(env, "nv.an", REG["password"])
    assert r.status_code == 403 and "chờ quản trị viên duyệt" in r.json()["detail"]
    assert login(env, "nv.an", "Sai-Mat-Khau-123").status_code == 401                          # sai mật khẩu: không lộ trạng thái
    admin_login(env)
    u = next(x for x in env.get("/api/v1/users").json() if x["username"] == "nv.an")
    assert u["pending"] and u["disabled"] and "password_hash" not in u
    assert (u["full_name"], u["birth_date"], u["phone"]) == ("Nguyễn Văn An", "2000-05-17", "0912345678")
    assert env.patch("/api/v1/users/nv.an", json={"disabled": False}, headers=H).status_code == 400   # phải duyệt
    env.post("/api/v1/auth/register", json={**REG, "username": "tam.thoi"}, headers=H)
    assert env.delete("/api/v1/users/tam.thoi", headers=H).status_code == 200                  # từ chối = xóa yêu cầu
    assert env.delete("/api/v1/users/admin", headers=H).status_code == 404                     # tài khoản đang dùng: không xóa
    assert env.post("/api/v1/users/nv.an/approve", json={"role": "lead"}, headers=H).status_code == 200
    env.post("/api/v1/auth/logout", headers=H)
    r = login(env, "nv.an", REG["password"])
    assert r.status_code == 200 and r.json()["role"] == "lead" and r.json()["must_change"] is False
    assert env.get("/api/v1/admin/sessions").status_code == 403                               # chỉ admin
    actions = [a[0] for a in env.audit]
    assert {"register", "user_approved", "user_rejected"} <= set(actions)
    assert all("0912345678" not in str(a) and "Nghệ An" not in str(a) for a in env.audit)     # thông tin cá nhân không vào nhật ký


def test_admin_creates_user_with_profile(env):
    admin_login(env)
    body = {"username": "ld.binh", "role": "lead", "password": "Tam-Thoi-Ld-2026", "full_name": "Trần Bình",
            "position": "Trưởng nhóm IR"}
    r = env.post("/api/v1/users", json=body, headers=H)
    assert r.status_code == 200 and r.json()["full_name"] == "Trần Bình" and "phone" not in r.json()
    r = env.post("/api/v1/users", json={**body, "username": "ld.cuong", "birth_date": "1900-01-01"}, headers=H)
    assert r.status_code == 400 and "ngày sinh" in r.json()["detail"]


def test_admin_sees_and_revokes_sessions(env):
    from siem.manager import auth
    admin_login(env)
    env.users.put(auth.new_user("an", "analyst", "Mat-Khau-An-2026", must_change=False))
    other = auth.sessions.create({"username": "an", "role": "analyst"}, "10.0.0.7")[1]
    ghost_token, _ = auth.sessions.create({"username": "da-xoa", "role": "analyst"}, "10.0.0.8")   # tài khoản không còn
    rows = env.get("/api/v1/admin/sessions").json()
    assert all(r["username"] != "da-xoa" for r in rows) and auth.sessions.get(ghost_token) is None
    me = next(r for r in rows if r["current"])
    assert me["username"] == "admin" and any(r["username"] == "an" and r["ip"] == "10.0.0.7" for r in rows)
    assert env.delete("/api/v1/admin/sessions/" + me["id"], headers=H).status_code == 400     # phiên của mình: Đăng xuất
    assert env.delete("/api/v1/admin/sessions/" + other.key, headers=H).status_code == 200
    assert all(r["username"] != "an" for r in env.get("/api/v1/admin/sessions").json())
    assert env.audit[-1][:3] == ("session_revoked", "success", "admin") and env.audit[-1][3]["target"] == "an"


def test_console_actions_are_logged_per_user(env):
    admin_login(env)
    body = {"agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4"}}
    assert env.post("/api/v1/actions", json=body, headers=H).status_code == 200
    act = [a for a in env.audit if a[0] == "activity"]
    assert act[-1][1:3] == ("success", "admin") and act[-1][3]["op"] == "action_requested"
    assert act[-1][3]["path"] == "/api/v1/actions" and act[-1][3]["change"] == "type=block_ip agent_id=001 ip=1.2.3.4"
    env.post("/api/v1/auth/logout", headers=H)
    n = len(env.audit)
    assert env.post("/api/v1/actions", json=body, headers=H).status_code == 401
    assert not [a for a in env.audit[n:] if a[0] == "activity"]                               # không phiên: không ghi


def test_admin_activity_query(env):
    from siem.manager import api
    seen = {}

    class ES:
        def search(self, **kw):
            seen.update(kw)
            return {"hits": {"hits": [{"_source": {"event": {"action": "console_login"}}}]}}
    admin_login(env)
    api._state["es"] = ES()
    assert env.get("/api/v1/admin/activity?user=an&kind=iam&since=24h").json() == [{"event": {"action": "console_login"}}]
    flt = seen["query"]["bool"]["filter"]
    assert {"term": {"event.module": "console"}} in flt and {"term": {"event.category": "iam"}} in flt
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in flt and seen["index"] == "siem-events-*"
    assert env.get("/api/v1/admin/activity?kind=xyz").status_code == 422


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
    doc = normalize(raw(action="activity", outcome="success", user="an", ip="10.0.0.9", role="analyst", op="alert_updated",
                        method="PATCH", path="/api/v1/alerts/abc", status=200, change="status=closed"))
    assert get(doc, "event.category") == "configuration" and get(doc, "event.action") == "console_alert_updated"
    assert get(doc, "url.path") == "/api/v1/alerts/abc" and get(doc, "http.response.status_code") == 200
    assert get(doc, "event.reason") == "status=closed" and get(doc, "user.name") == "an"
    doc = normalize(raw(action="register", outcome="success", user="nv.an", ip="10.0.0.9"))
    assert get(doc, "event.category") == "iam" and get(doc, "event.type") == "creation"


# ------------------------------------------------------------------ Grafana sau manager (auth proxy, dùng chung phiên)
@pytest.fixture()
def grafana(env):
    import httpx
    from siem.manager import grafana_proxy
    seen = []

    def upstream(req):
        seen.append(req)
        return httpx.Response(200, headers=[("content-type", "text/html"), ("set-cookie", "a=1"), ("set-cookie", "b=2")],
                              stream=httpx.ByteStream(b"<html>grafana</html>"))   # như upstream thật: chưa đọc body
    grafana_proxy.set_client(httpx.AsyncClient(transport=httpx.MockTransport(upstream), base_url="http://grafana-internal:3000"))
    yield seen
    grafana_proxy.set_client(None)


NAV = {"Sec-Fetch-Mode": "navigate"}


def test_grafana_requires_console_session(env, grafana):
    r = env.get("/grafana/d/siem-overview?orgId=1", headers=NAV, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=%2Fgrafana%2Fd%2Fsiem-overview%3ForgId%3D1"
    assert env.post("/grafana/api/ds/query", json={}).status_code == 401            # request API: 401, không chuyển trang
    login(env, "admin", ADMIN_TMP)                                                   # mật khẩu tạm -> phải đổi trước
    r = env.get("/grafana/", headers=NAV, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?change=1&next=%2Fgrafana%2F")
    assert grafana == []                                                             # chưa request nào tới Grafana


def test_grafana_identity_headers_and_role_mapping(env, grafana):
    activate(env, "lan", "lead")
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    env.cookies.set("grafana_x", "1", domain=HOST)
    r = env.get("/grafana/d/x?orgId=1", headers={**NAV, "X-WEBAUTH-USER": "admin", "X-WEBAUTH-ROLE": "Admin"})
    assert r.status_code == 200 and r.text == "<html>grafana</html>"
    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]                       # nhiều Set-Cookie giữ nguyên
    req = grafana[-1]
    assert str(req.url) == "http://grafana-internal:3000/grafana/d/x?orgId=1"
    assert req.headers.get_list("x-webauth-user") == ["an"]                          # header giả mạo bị thay
    assert req.headers["x-webauth-role"] == "Viewer"
    assert "grafana_x=1" in req.headers["cookie"] and "siem_session" not in req.headers["cookie"]
    login(env, "lan", "Rieng-Tu-Zx9-3-2026")
    env.get("/grafana/", headers=NAV)
    assert grafana[-1].headers["x-webauth-role"] == "Editor"
    admin_login(env)
    env.get("/grafana/", headers=NAV)
    assert grafana[-1].headers["x-webauth-role"] == "Admin"


def test_grafana_stale_session_cookies_removed(env, grafana):
    """Cookie phiên Grafana cũ (thời Grafana mở ở :3000 có form đăng nhập) làm frontend Grafana gọi rotate -> 401 -> tải
    lại trang mãi. Không chuyển tiếp sang Grafana và xóa trong trình duyệt."""
    admin_login(env)
    r = env.get("/grafana/d/x", headers={**NAV, "Cookie": "grafana_session_expiry=1700000000; grafana_session=abc; "
                                         "grafana_x=1; siem_session=" + env.cookies.get("siem_session")})
    assert r.status_code == 200
    assert grafana[-1].headers["cookie"] == "grafana_x=1"
    cleared = [c for c in r.headers.get_list("set-cookie") if "Max-Age=0" in c]
    assert sorted(c.split(";")[0] + c.split(";")[1] for c in cleared) == sorted(
        f"{n}= Path={p}" for n in ("grafana_session", "grafana_session_expiry") for p in ("/", "/grafana", "/grafana/"))
    r = env.get("/grafana/d/x", headers=NAV)                                         # không có cookie cũ: không xóa gì
    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]


def test_grafana_never_sets_session_cookies(env):
    """Grafana không có phiên riêng: cookie phiên Grafana đặt ra (vd bật nhầm login token) không tới trình duyệt."""
    import httpx
    from siem.manager import grafana_proxy
    grafana_proxy.set_client(httpx.AsyncClient(base_url="http://g", transport=httpx.MockTransport(lambda req: httpx.Response(
        200, headers=[("set-cookie", "grafana_session=t; Path=/grafana"), ("set-cookie", "grafana_session_expiry=1; Path=/grafana"),
                      ("set-cookie", "a=1")], stream=httpx.ByteStream(b"ok")))))
    try:
        admin_login(env)
        assert env.get("/grafana/d/x", headers=NAV).headers.get_list("set-cookie") == ["a=1"]
    finally:
        grafana_proxy.set_client(None)


def test_grafana_auto_refresh_does_not_extend_session(env, grafana):
    admin_login(env)
    env.clock.now += 20 * 60
    assert env.post("/grafana/api/ds/query", json={}).status_code == 200            # dashboard tự làm mới
    env.clock.now += 11 * 60                                                         # 31 phút không thao tác thật
    assert env.post("/grafana/api/ds/query", json={}).status_code == 401
    admin_login(env)
    for _ in range(3):                                                               # mở trang / xem dashboard: gia hạn
        env.clock.now += 25 * 60
        assert env.get("/grafana/api/dashboards/uid/siem-overview").status_code == 200


def test_grafana_folder_permissions_set_once():
    import asyncio
    import httpx
    from siem.manager import grafana_proxy
    perms, posts, deleted = [{"userId": 7, "permission": 4, "role": ""}], [], []
    legacy = {"old1": [], "old2": [{"uid": "mine", "type": "dash-db"}]}      # thư mục cũ: rỗng / có dashboard tự lưu

    def upstream(req):
        assert req.headers["x-webauth-user"] == "admin"
        if req.url.path == "/grafana/api/folders":
            return httpx.Response(200, json=[{"uid": "abc", "title": "SOC Platform"}, {"uid": "old1", "title": "SIEM-XDR"},
                                             {"uid": "old2", "title": "SIEM-XDR"}, {"uid": "x", "title": "Khác"}])
        if req.url.path == "/grafana/api/search":
            return httpx.Response(200, json=legacy[req.url.params["folderUIDs"]])
        if req.method == "DELETE":
            deleted.append(req.url.path)
            return httpx.Response(200, json={"message": "ok"})
        if req.method == "POST":
            posts.append(json.loads(req.content))
            perms[:] = [{**p, "role": p.get("role", "")} for p in posts[-1]["items"]]
            return httpx.Response(200, json={"message": "ok"})
        return httpx.Response(200, json=perms)
    grafana_proxy.set_client(httpx.AsyncClient(transport=httpx.MockTransport(upstream), base_url="http://g"))
    try:
        assert asyncio.run(grafana_proxy.ensure_folder_permissions(attempts=1, delay=0))
        assert posts == [{"items": [{"userId": 7, "permission": 4},                  # quyền theo user giữ nguyên
                                    {"role": "Viewer", "permission": 1}, {"role": "Editor", "permission": 2}]}]
        grafana_proxy.set_client(httpx.AsyncClient(transport=httpx.MockTransport(upstream), base_url="http://g"))
        assert asyncio.run(grafana_proxy.ensure_folder_permissions(attempts=1, delay=0))
        assert len(posts) == 1                                                       # đã có quyền -> không ghi đè
        assert deleted == ["/grafana/api/folders/old1"] * 2           # chỉ xóa thư mục cũ đã rỗng, không đụng thư mục khác
    finally:
        grafana_proxy.set_client(None)


def test_promote_shadow_rule_needs_detection_engineer(env, monkeypatch):
    from siem.manager import api
    monkeypatch.setattr(api.ai_deploy, "promote", lambda es, rid, who, *a, **kw: {"rule_id": rid, "by": who})
    monkeypatch.setattr(api, "refresh_catalog", lambda: None)
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    assert env.post("/api/v1/rules/AI-077/promote", json={}, headers=H).status_code == 403
    pw = activate(env, "de", "detection")
    login(env, "de", pw)
    assert env.post("/api/v1/rules/AI-077/promote", json={}, headers=H).json() == {"rule_id": "AI-077", "by": "de"}
    assert env.get("/api/v1/rules/KHONG-CO/shadow").status_code == 404


# ------------------------------------------------------------------ xác thực 2 lớp (TOTP)
def test_totp_matches_rfc6238_vector():
    import base64
    from siem.manager import auth
    secret = base64.b32encode(b"12345678901234567890").decode()       # khóa mẫu của RFC 6238 phụ lục B (SHA-1)
    assert auth.totp_at(secret, 59 // 30) == "287082"                     # T = 59 giây: 94287082 (8 số) -> 6 số cuối
    assert auth.totp_at(secret, 1111111109 // 30) == "081804"            # 07081804


def _code(env, secret, offset=0):
    from siem.manager import auth
    return auth.totp_at(secret, int(env.clock.now // auth.TOTP_STEP) + offset)


def test_mfa_enroll_login_and_replay(env):
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    r = env.post("/api/v1/auth/mfa/setup", json={}, headers=H)
    secret = r.json()["secret"]
    assert r.status_code == 200 and r.json()["otpauth_uri"].startswith("otpauth://totp/SOC%20Platform:an?secret=")
    assert env.post("/api/v1/auth/mfa/enable", json={"code": "000000"}, headers=H).status_code == 400
    r = env.post("/api/v1/auth/mfa/enable", json={"code": _code(env, secret)}, headers=H)
    assert r.status_code == 200 and r.json()["mfa_enabled"] is True
    listed = [u for u in (admin_login(env) or env.get("/api/v1/users").json()) if u["username"] == "an"][0]
    assert listed["mfa_enabled"] is True and "mfa" not in listed and secret not in str(listed)   # không lộ khóa
    env.clock.now += 90                                                   # bước thời gian mới
    r = login(env, "an", pw)
    assert r.status_code == 401 and r.json()["detail"]["mfa"] == "required"       # mật khẩu đúng: hỏi mã
    r = env.post("/api/v1/auth/login", json={"username": "an", "password": pw, "otp": "123456"}, headers=H)
    assert r.status_code == 401 and r.json()["detail"]["mfa"] == "invalid"
    assert env.audit[-1][3].get("reason") == "bad_otp"
    code = _code(env, secret)
    assert env.post("/api/v1/auth/login", json={"username": "an", "password": pw, "otp": code}, headers=H).status_code == 200
    r = env.post("/api/v1/auth/login", json={"username": "an", "password": pw, "otp": code}, headers=H)
    assert r.status_code == 401                                           # cùng mã dùng lại: từ chối
    assert env.post("/api/v1/auth/login", json={"username": "an", "password": "sai-mat-khau", "otp": code},
                    headers=H).json()["detail"] == "sai tên đăng nhập hoặc mật khẩu"


def test_mfa_required_role_and_admin_reset(env, monkeypatch):
    monkeypatch.setattr(settings, "CONSOLE_MFA_REQUIRED_ROLES", {"lead"})
    pw = activate(env, "ld", "lead")
    me = login(env, "ld", pw).json()
    assert me["must_mfa"] is True and me["mfa_required"] is True
    r = env.get("/api/v1/stats")
    assert r.status_code == 403 and "xác thực 2 lớp" in r.json()["detail"]
    r = env.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?mfa=1&next=%2F"
    secret = env.post("/api/v1/auth/mfa/setup", json={}, headers=H).json()["secret"]
    assert env.post("/api/v1/auth/mfa/enable", json={"code": _code(env, secret)}, headers=H).json()["must_mfa"] is False
    assert env.get("/api/v1/stats").status_code == 200
    r = env.post("/api/v1/auth/mfa/disable", json={"password": pw}, headers=H)
    assert r.status_code == 400 and "bắt buộc" in r.json()["detail"]
    admin_login(env)
    assert env.patch("/api/v1/users/ld", json={"mfa_reset": True}, headers=H).json()["mfa_enabled"] is False
    assert ("user_updated", "success", "admin", {"target": "ld", "change": "đặt lại xác thực 2 lớp"}) in env.audit
    assert login(env, "ld", pw).json()["must_mfa"] is True                # mất điện thoại: bật lại từ đầu


# ------------------------------------------------------------------ threat hunting, giao ca, AI hỗ trợ (manager/soc.py)
class IdxES:
    """ES giả theo index: index / get / update có seq_no như ES thật."""

    def __init__(self):
        self.docs, self.seq = {}, {}

    def index(self, index, document, id=None, **_):
        id = id or f"auto{len(self.docs)}"
        self.docs[(index, id)], self.seq[(index, id)] = dict(document), 1
        return {"_id": id}

    def get(self, index, id):
        from elasticsearch import NotFoundError
        if (index, id) not in self.docs:
            raise NotFoundError("not found", meta=type("M", (), {"status": 404})(), body={})
        return {"_source": dict(self.docs[(index, id)]), "_seq_no": self.seq[(index, id)], "_primary_term": 1}

    def update(self, index, id, doc, if_seq_no=None, **_):
        if if_seq_no is not None and if_seq_no != self.seq[(index, id)]:
            raise RuntimeError("conflict")
        self.docs[(index, id)].update(doc)
        self.seq[(index, id)] += 1


def test_threat_hunting_log(env):
    from siem.manager import api
    fake = IdxES()
    api._state["es"] = fake
    pw_an, pw_hu = activate(env, "an", "analyst"), activate(env, "hu", "hunter")
    body = {"title": "Kerberoasting trên DC", "hypothesis": "Tài khoản domain xin vé TGS RC4 hàng loạt",
            "techniques": ["T1558.003"], "data_sources": ["4769"], "queries": "winlog.event_id:4769"}
    login(env, "an", pw_an)
    assert env.post("/api/v1/hunts", json=body, headers=H).status_code == 403            # analyst không có quyền hunt
    assert len(env.get("/api/v1/hunts/starters").json()) == 5
    login(env, "hu", pw_hu)
    assert env.post("/api/v1/hunts", json=body | {"techniques": ["T15"]}, headers=H).status_code == 400
    h = env.post("/api/v1/hunts", json=body, headers=H).json()
    assert h["status"] == "planned" and h["owner"] == "hu"
    patch = lambda **b: env.patch(f"/api/v1/hunts/{h['id']}", json=b, headers=H)     # noqa: E731
    assert patch(status="in_progress").status_code == 200
    r = patch(status="completed")
    assert r.status_code == 400 and "kết luận" in r.json()["detail"]
    r = patch(status="completed", findings="Không thấy vé RC4 bất thường trong 30 ngày", outcome="no_threat",
              data_gaps=["chưa thu 4769 từ DC2"])
    doc = fake.docs[("siem-hunts", h["id"])]
    assert r.status_code == 200 and doc["status"] == "completed" and doc["completed_at"] and doc["data_gaps"] == ["chưa thu 4769 từ DC2"]
    assert [n["text"] for n in doc["notes"]][-1] == "trạng thái: in_progress -> completed"


def test_shift_handover_summary_and_saved_record(env, monkeypatch):
    from siem.manager import api
    fake = IdxES()
    api._state["es"] = fake
    now = datetime.now(timezone.utc)
    rows = {
        settings.IDX_ALERTS: [
            {"_id": "a1", "priority": "P1", "@timestamp": "t1", "rule": {"name": "Webshell"}, "alert": {"status": "open"},
             "soar": {"results": [{"action": "isolate_host", "status": "awaiting_approval"}]}},
            {"_id": "a2", "priority": "P3", "rule": {"name": "Quét cổng"}, "alert": {"status": "acknowledged"}},
            {"_id": "h1", "priority": "P2", "rule": {"name": "Agent mất kết nối"}, "alert": {"status": "open", "source": "health"}}],
        settings.IDX_CASES: [
            {"_id": "c1", "title": "Webshell", "priority": "P1", "status": "open", "sla_due": (now - timedelta(minutes=5)).isoformat()},
            {"_id": "c2", "title": "Ransomware", "priority": "P1", "status": "in_progress", "acknowledged_at": "x",
             "incident": {"declared_at": "y"}}],
        settings.IDX_ACTIONS: [{"agent_id": "001", "target": "203.0.113.9", "expires_at": (now + timedelta(hours=2)).isoformat()}],
    }
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: rows.get(index, []))
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    s = env.get("/api/v1/handover").json()
    assert s["alerts_open"] == 3 and s["alerts_by_priority"] == {"P1": 1, "P2": 1, "P3": 1}
    assert [a["_id"] for a in s["alerts_top"]] == ["a1", "h1"] and [a["_id"] for a in s["awaiting_approval"]] == ["a1"]
    assert s["cases_overdue"] == 1 and [c["_id"] for c in s["major_incidents"]] == ["c2"]
    assert s["blocks_expiring"][0]["target"] == "203.0.113.9" and [a["_id"] for a in s["platform_incidents"]] == ["h1"]
    r = env.post("/api/v1/handover", json={"note": "Ca đêm: theo dõi case c1", "to": "binh"}, headers=H).json()
    saved = fake.docs[("siem-handovers", r["_id"])]
    assert saved["by"] == "an" and saved["to"] == "binh" and saved["cases_overdue"] == 1


def test_ai_assist_jobs_and_feedback(env):
    from siem.manager import api
    fake = IdxES()
    api._state["es"] = fake
    pw = activate(env, "an", "analyst")
    login(env, "an", pw)
    post = lambda **b: env.post("/api/v1/ai/assist", json=b, headers=H)              # noqa: E731
    assert post(task="summary").status_code == 400                                   # tóm tắt cần alert / case
    assert post(task="report", target_type="alert", target_id="a1").status_code == 400
    assert post(task="query").status_code == 400
    r = post(task="summary", target_type="case", target_id="c1").json()
    job = fake.docs[(settings.IDX_AI_JOBS, r["_id"])]
    assert job["kind"] == "triage" and job["status"] == "pending" and job["requested_by"] == "an" and "AI" in job["label"]
    fb = lambda useful: env.post(f"/api/v1/ai/assist/{r['_id']}/feedback", json={"useful": useful}, headers=H)  # noqa: E731
    assert fb(True).status_code == 409                                               # chưa xong
    fake.docs[(settings.IDX_AI_JOBS, r["_id"])]["status"] = "done"
    assert fb(False).json()["feedback"]["useful"] is False and fake.docs[(settings.IDX_AI_JOBS, r["_id"])]["feedback"]["by"] == "an"
    assert env.get("/api/v1/ai/assist/khong-co").status_code == 404
