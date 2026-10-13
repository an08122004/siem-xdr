"""Đăng nhập SOC console bằng tài khoản riêng từng người (thay cho API key dùng chung).

- Mật khẩu băm scrypt (salt ngẫu nhiên riêng từng tài khoản), lưu ở index Elasticsearch `console-users`. Index nằm
  NGOÀI `siem-*` nên Grafana và tài khoản chỉ đọc `analyst` (role siem_reader) không đọc được hash.
- Phiên: token ngẫu nhiên 256 bit trong cookie HttpOnly + Secure + SameSite=Strict; phía server chỉ giữ SHA-256 của
  token, trong bộ nhớ manager (manager khởi động lại = mọi người đăng nhập lại). Hết hạn sau CONSOLE_IDLE_MINUTES
  không thao tác (request tự làm mới của console gửi header X-Auto-Refresh, không tính là thao tác) và tối đa
  CONSOLE_SESSION_HOURS kể từ lúc đăng nhập.
- Chống CSRF: cookie SameSite=Strict, và request thay đổi dữ liệu phải có header X-Requested-With (trang web khác
  không gửi được header tự đặt vì manager không bật CORS).
- Chống dò mật khẩu: sai CONSOLE_MAX_FAILURES lần trong 15 phút (theo tên đăng nhập hoặc theo IP) -> khóa 15 phút.
  Tên không tồn tại vẫn tốn đúng một lần tính scrypt -> không dò được tên qua thời gian phản hồi.
- Vai trò theo cơ cấu SOC (SOC-OPERATIONS.md mục 1): analyst (Tier 1), lead (Tier 2 IR), hunter (Tier 3), detection
  (Detection Engineer), manager (SOC Manager), admin. Quyền tính theo năng lực (PERMISSIONS), không theo thang:
  Detection Engineer duyệt rule nhưng không cô lập máy; người xử lý cảnh báo không tự duyệt rule mình dùng.
- Người thực hiện mọi thao tác lấy từ phiên (không tự khai) -> lịch sử case / duyệt AI đáng tin, và quy định
  "ngoại lệ AI cần 2 người KHÁC NHAU duyệt" có hiệu lực thật.
- Đăng nhập / đăng xuất / đổi mật khẩu / quản lý tài khoản được gửi vào Kafka thành event của chính SIEM
  (event_type console_auth): lưu trong siem-events-*, hiện trên Grafana (Phiên đăng nhập), rule AUTH-001 áp dụng được.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

from elasticsearch import ConflictError, NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from .. import bus, settings, store

log = logging.getLogger("manager.auth")

# Vai trò -> quyền. Quyền:
#   triage   xử lý alert / case, chặn IP, kill tiến trình, task cần Analyst L1 duyệt
#   contain  cô lập / bỏ cô lập máy, duyệt bước SOAR cô lập, task cần Trưởng nhóm IR duyệt, nâng ưu tiên case
#   hunt     ghi nhật ký threat hunting
#   rules    duyệt / từ chối / gỡ đề xuất AI, bật chính thức rule đang chạy bóng, chạy phân tích AI
#   declare  tuyên bố sự cố lớn (P1), ghi nhận đã thông báo cơ quan chức năng
#   users    quản lý tài khoản
# Trước 13/10/2026 chỉ có thang analyst < lead < admin, và analyst duyệt được cả rule AI do chính mình xử lý cảnh báo.
PERMISSIONS: dict[str, frozenset[str]] = {
    "analyst": frozenset({"triage"}),                                       # Tier 1, CTI analyst
    "lead": frozenset({"triage", "contain"}),                               # Tier 2 Incident Responder
    "hunter": frozenset({"triage", "contain", "hunt"}),                     # Tier 3 Threat Hunter / DFIR
    "detection": frozenset({"rules", "hunt"}),                              # Detection Engineer
    "manager": frozenset({"triage", "contain", "hunt", "declare"}),         # SOC Manager
    "admin": frozenset({"triage", "contain", "hunt", "rules", "declare", "users"}),   # SOC Platform Engineer
}
ROLES = tuple(PERMISSIONS)
ROLE_LABELS = {"analyst": "Analyst (Tier 1)", "lead": "Trưởng nhóm IR (Tier 2)", "hunter": "Threat Hunter (Tier 3)",
               "detection": "Detection Engineer", "manager": "SOC Manager", "admin": "Quản trị nền tảng"}
ROLE_PATTERN = "^(" + "|".join(ROLES) + ")$"


def has(role: str, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, frozenset())
USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{1,31}$"
COOKIE = "siem_session"
CSRF_HEADER, CSRF_VALUE = "x-requested-with", "siem-console"
MIN_PASSWORD = 12
MIN_DISTINCT = 6          # số ký tự khác nhau tối thiểu trong mật khẩu


# --------------------------------------------------------------------------- mật khẩu
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(expected))
        return hmac.compare_digest(got, expected)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(16))   # tên không tồn tại vẫn tính scrypt như thật


def password_problem(password: str, username: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"mật khẩu tối thiểu {MIN_PASSWORD} ký tự"
    if username and username.lower() in password.lower():
        return "mật khẩu không được chứa tên đăng nhập"
    if len(set(password)) < MIN_DISTINCT:
        return f"mật khẩu quá đơn giản (cần ít nhất {MIN_DISTINCT} ký tự khác nhau)"
    return None


# --------------------------------------------------------------------------- tài khoản
def new_user(username: str, role: str, password: str, must_change: bool = True) -> dict[str, Any]:
    now = store.now_iso()
    return {"username": username, "role": role, "password_hash": hash_password(password), "must_change": must_change,
            "disabled": False, "created_at": now, "updated_at": now, "last_login": None}


def public(user: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in user.items() if k != "password_hash"}


class UserStore:
    """Tài khoản console trong Elasticsearch (index console-users, id = tên đăng nhập)."""

    def __init__(self, es):
        self.es = es

    def get(self, username: str) -> dict[str, Any] | None:
        try:
            return self.es.get(index=settings.IDX_USERS, id=username)["_source"]
        except NotFoundError:
            return None

    def create(self, user: dict[str, Any]) -> bool:
        try:
            self.es.index(index=settings.IDX_USERS, id=user["username"], document=user, op_type="create",
                          refresh="wait_for")
            return True
        except ConflictError:
            return False

    def put(self, user: dict[str, Any]) -> None:
        self.es.index(index=settings.IDX_USERS, id=user["username"], document=user, refresh="wait_for")

    def list(self) -> list[dict[str, Any]]:
        try:
            res = self.es.search(index=settings.IDX_USERS, size=500, query={"match_all": {}})
        except NotFoundError:
            return []
        return sorted((h["_source"] for h in res["hits"]["hits"]), key=lambda u: u["username"])

    def count(self) -> int:
        """0 nếu index chưa có; lỗi khác (ES tạm lỗi) thì raise — không được coi là 'chưa có tài khoản'."""
        try:
            return self.es.count(index=settings.IDX_USERS)["count"]
        except NotFoundError:
            return 0


class MemoryUserStore(UserStore):
    """Dùng cho test."""

    def __init__(self):
        self.users: dict[str, dict[str, Any]] = {}

    def get(self, username):
        u = self.users.get(username)
        return dict(u) if u else None

    def create(self, user):
        if user["username"] in self.users:
            return False
        self.users[user["username"]] = dict(user)
        return True

    def put(self, user):
        self.users[user["username"]] = dict(user)

    def list(self):
        return [dict(u) for _, u in sorted(self.users.items())]

    def count(self):
        return len(self.users)


# --------------------------------------------------------------------------- phiên
@dataclass
class Session:
    key: str               # SHA-256 của token (server không giữ token gốc)
    username: str
    role: str
    ip: str
    created: float
    last_active: float
    must_change: bool


class Sessions:
    def __init__(self):
        self._d: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _expired(s: Session, now: float) -> bool:
        return now - s.last_active > settings.CONSOLE_IDLE_MINUTES * 60 or \
            now - s.created > settings.CONSOLE_SESSION_HOURS * 3600

    def create(self, user: dict[str, Any], ip: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = time.time()
        s = Session(self._key(token), user["username"], user["role"], ip, now, now, bool(user.get("must_change")))
        with self._lock:
            # dọn phiên bỏ dở (đóng trình duyệt không đăng xuất) để bộ nhớ không phình theo thời gian
            for k in [k for k, x in self._d.items() if self._expired(x, now)]:
                del self._d[k]
            self._d[s.key] = s
        return token, s

    def __len__(self) -> int:
        return len(self._d)

    def get(self, token: str, touch: bool = True) -> Session | None:
        now = time.time()
        with self._lock:
            s = self._d.get(self._key(token))
            if not s:
                return None
            if self._expired(s, now):
                del self._d[s.key]
                return None
            if touch:
                s.last_active = now
            return s

    def drop(self, token: str) -> None:
        with self._lock:
            self._d.pop(self._key(token), None)

    def drop_user(self, username: str, keep: Session | None = None) -> None:
        with self._lock:
            for k in [k for k, s in self._d.items() if s.username == username and s is not keep]:
                del self._d[k]


class Throttle:
    """Đếm lần đăng nhập sai theo khóa (user:<tên>, ip:<địa chỉ>) trong cửa sổ 15 phút."""
    WINDOW = LOCK = 15 * 60

    def __init__(self):
        self.failures: dict[str, list[float]] = defaultdict(list)
        self.locked: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, *keys: str) -> float:
        now = time.time()
        with self._lock:
            return max([self.locked[k] - now for k in keys if self.locked.get(k, 0) > now] or [0.0])

    MAX_KEYS = 10_000      # thử hàng loạt tên đăng nhập ngẫu nhiên không được làm bảng đếm phình mãi

    def failure(self, *keys: str) -> bool:
        now = time.time()
        became_locked = False
        with self._lock:
            if len(self.failures) + len(self.locked) > self.MAX_KEYS:
                for k in [k for k, ts in self.failures.items() if not ts or now - ts[-1] >= self.WINDOW]:
                    del self.failures[k]
                for k in [k for k, until in self.locked.items() if until <= now]:
                    del self.locked[k]
            for k in keys:
                self.failures[k] = [t for t in self.failures[k] if now - t < self.WINDOW] + [now]
                if len(self.failures[k]) >= settings.CONSOLE_MAX_FAILURES:
                    self.locked[k] = now + self.LOCK
                    self.failures[k] = []
                    became_locked = True
        return became_locked

    def success(self, key: str) -> None:
        with self._lock:
            self.failures.pop(key, None)


# --------------------------------------------------------------------------- nhật ký
class Audit:
    """Gửi sự kiện đăng nhập / quản lý tài khoản vào Kafka siem.raw (best effort: Kafka lỗi không chặn đăng nhập)."""

    def __init__(self):
        self._producer = None

    def __call__(self, action: str, outcome: str, user: str, ip: str, **extra: Any) -> None:
        ev = {"timestamp": store.now_iso(), "agent_id": "soc-console", "hostname": "soc-console", "source": "console",
              "event_type": "console_auth",
              "data": {"action": action, "outcome": outcome, "user": user, "ip": ip,
                       **{k: v for k, v in extra.items() if v is not None}}}
        log.info("console %s %s: user=%s ip=%s %s", action, outcome, user, ip, extra or "")
        try:
            if self._producer is None:
                self._producer = bus.producer()
            bus.send(self._producer, settings.TOPIC_RAW, ev, key="soc-console")
        except Exception as e:  # noqa: BLE001
            log.warning("không gửi được nhật ký đăng nhập vào Kafka: %s", e)


users: UserStore | None = None
sessions = Sessions()
throttle = Throttle()
audit: Callable[..., None] = Audit()


def setup(es) -> None:
    """Gọi khi manager khởi động: gắn kho tài khoản và tạo tài khoản admin đầu tiên nếu chưa có ai."""
    global users
    users = UserStore(es)
    bootstrap_admin()


def bootstrap_admin() -> None:
    try:
        if users.count():
            return
    except Exception as e:  # noqa: BLE001 - ES tạm lỗi: KHÔNG tạo (có thể ghi đè admin đang có)
        log.error("không kiểm tra được tài khoản console, bỏ qua tạo admin: %s", e)
        return
    if not settings.CONSOLE_ADMIN_PASSWORD:
        log.error("chưa có tài khoản console nào và thiếu secret console_admin_password")
        return
    users.create(new_user("admin", "admin", settings.CONSOLE_ADMIN_PASSWORD, must_change=True))
    log.warning("đã tạo tài khoản console 'admin' (mật khẩu: secrets/console_admin_password, phải đổi khi đăng nhập lần đầu)")


# --------------------------------------------------------------------------- dependency cho API
def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _check_csrf(request: Request) -> None:
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(403, "thiếu header X-Requested-With (chống CSRF)")


def session(request: Request) -> Session:
    """Phiên hợp lệ (kể cả khi đang bị buộc đổi mật khẩu)."""
    token = request.cookies.get(COOKIE)
    s = sessions.get(token, touch=request.headers.get("x-auto-refresh") != "1") if token else None
    if not s:
        raise HTTPException(401, "chưa đăng nhập hoặc phiên đã hết hạn")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        _check_csrf(request)
    return s


def current_user(s: Session = Depends(session)) -> Session:
    if s.must_change:
        raise HTTPException(403, "phải đổi mật khẩu trước khi dùng console")
    return s


PERMISSION_TEXT = {"triage": "xử lý cảnh báo", "contain": "cô lập máy (Trưởng nhóm IR)", "hunt": "threat hunting",
                   "rules": "duyệt rule (Detection Engineer)", "declare": "tuyên bố sự cố (SOC Manager)",
                   "users": "quản lý tài khoản (admin)"}


def require_perm(perm: str) -> Callable[..., Session]:
    if perm not in PERMISSION_TEXT:
        raise ValueError(f"quyền không tồn tại: {perm}")

    def dep(s: Session = Depends(current_user)) -> Session:
        if not has(s.role, perm):
            raise HTTPException(403, f"cần quyền {PERMISSION_TEXT[perm]}; vai trò {s.role} không có quyền này")
        return s
    return dep


# --------------------------------------------------------------------------- API đăng nhập / tài khoản
router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordBody(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=1, max_length=256)


class NewUser(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    role: str = Field(pattern=ROLE_PATTERN)
    password: str = Field(min_length=1, max_length=256)


class UserUpdate(BaseModel):
    role: str | None = Field(None, pattern=ROLE_PATTERN)
    disabled: bool | None = None
    password: str | None = Field(None, min_length=1, max_length=256)   # đặt lại -> buộc đổi ở lần đăng nhập sau


def _me(s: Session) -> dict[str, Any]:
    return {"username": s.username, "role": s.role, "role_label": ROLE_LABELS.get(s.role, s.role),
            "permissions": sorted(PERMISSIONS.get(s.role, ())), "must_change": s.must_change,
            "idle_minutes": settings.CONSOLE_IDLE_MINUTES, "session_hours": settings.CONSOLE_SESSION_HOURS}


@router.get("/api/v1/auth/roles")
def roles(s: Session = Depends(current_user)) -> list[dict[str, Any]]:
    """Danh sách vai trò và quyền (trang Tài khoản hiển thị, chọn vai trò)."""
    return [{"role": r, "label": ROLE_LABELS[r], "permissions": sorted(p)} for r, p in PERMISSIONS.items()]


@router.post("/api/v1/auth/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    _check_csrf(request)
    ip, username = client_ip(request), body.username.strip().lower()
    keys = (f"user:{username}", f"ip:{ip}")
    if (wait := throttle.wait(*keys)):
        audit("login", "failure", username, ip, reason="locked")
        raise HTTPException(429, f"đăng nhập sai quá nhiều lần, thử lại sau {int(wait // 60) + 1} phút")
    user = users.get(username)
    valid = verify_password(body.password, user["password_hash"] if user else _DUMMY_HASH)
    if not (valid and user and not user.get("disabled")):
        locked = throttle.failure(*keys)
        audit("login", "failure", username, ip, reason="locked" if locked else "bad_credentials")
        raise HTTPException(401, "sai tên đăng nhập hoặc mật khẩu")
    throttle.success(keys[0])
    token, s = sessions.create(user, ip)
    user["last_login"] = store.now_iso()
    users.put(user)
    response.set_cookie(COOKIE, token, httponly=True, secure=True, samesite="strict", path="/",
                        max_age=settings.CONSOLE_SESSION_HOURS * 3600)
    audit("login", "success", username, ip, role=user["role"])
    return _me(s)


@router.post("/api/v1/auth/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    token = request.cookies.get(COOKIE)
    s = sessions.get(token, touch=False) if token else None
    if token:
        sessions.drop(token)
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    if s:
        audit("logout", "success", s.username, client_ip(request), role=s.role)
    return {"ok": True}


@router.get("/api/v1/auth/policy")
def policy() -> dict[str, int]:
    """Chính sách đăng nhập (công khai) để trang đăng nhập hiển thị đúng con số đang cấu hình."""
    return {"idle_minutes": settings.CONSOLE_IDLE_MINUTES, "session_hours": settings.CONSOLE_SESSION_HOURS,
            "max_failures": settings.CONSOLE_MAX_FAILURES, "lock_minutes": Throttle.LOCK // 60,
            "min_password": MIN_PASSWORD, "min_distinct": MIN_DISTINCT}


@router.get("/logout", include_in_schema=False)
def logout_page(request: Request) -> RedirectResponse:
    """Đăng xuất bằng đường link (nút Sign out của Grafana chuyển tới đây) -> về trang đăng nhập."""
    token = request.cookies.get(COOKIE)
    s = sessions.get(token, touch=False) if token else None
    if token:
        sessions.drop(token)
    resp = RedirectResponse("/login?reason=logged_out", status_code=303)
    resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    if s:
        audit("logout", "success", s.username, client_ip(request), role=s.role)
    return resp


@router.get("/api/v1/auth/me")
def me(s: Session = Depends(session)) -> dict[str, Any]:
    return _me(s)


@router.post("/api/v1/auth/password")
def change_password(body: PasswordBody, request: Request, s: Session = Depends(session)) -> dict[str, Any]:
    user, ip = users.get(s.username), client_ip(request)
    if not user or not verify_password(body.current, user["password_hash"]):
        throttle.failure(f"user:{s.username}", f"ip:{ip}")
        audit("password_changed", "failure", s.username, ip, reason="bad_current_password")
        raise HTTPException(400, "mật khẩu hiện tại không đúng")
    if (problem := password_problem(body.new, s.username)):
        raise HTTPException(400, problem)
    if verify_password(body.new, user["password_hash"]):
        raise HTTPException(400, "mật khẩu mới phải khác mật khẩu cũ")
    user.update(password_hash=hash_password(body.new), must_change=False, updated_at=store.now_iso())
    users.put(user)
    sessions.drop_user(s.username, keep=s)          # các phiên khác của tài khoản này phải đăng nhập lại
    s.must_change = False
    audit("password_changed", "success", s.username, ip, role=s.role)
    return _me(s)


@router.get("/api/v1/users")
def list_users(s: Session = Depends(require_perm("users"))) -> list[dict[str, Any]]:
    return [public(u) for u in users.list()]


@router.post("/api/v1/users")
def create_user(body: NewUser, request: Request, s: Session = Depends(require_perm("users"))) -> dict[str, Any]:
    if (problem := password_problem(body.password, body.username)):
        raise HTTPException(400, problem)
    user = new_user(body.username, body.role, body.password, must_change=True)
    if not users.create(user):
        raise HTTPException(409, f"tài khoản {body.username} đã tồn tại")
    audit("user_created", "success", s.username, client_ip(request), target=body.username, target_role=body.role)
    return public(user)


@router.patch("/api/v1/users/{username}")
def update_user(username: str, body: UserUpdate, request: Request,
                s: Session = Depends(require_perm("users"))) -> dict[str, Any]:
    user = users.get(username)
    if not user:
        raise HTTPException(404, "không có tài khoản này")
    demote = body.role is not None and body.role != "admin" and user["role"] == "admin"
    if username == s.username and (body.disabled or demote):
        raise HTTPException(400, "không tự khóa hoặc tự hạ quyền chính mình")
    if (body.disabled or demote) and user["role"] == "admin" and not any(
            u["role"] == "admin" and not u.get("disabled") and u["username"] != username for u in users.list()):
        raise HTTPException(400, "phải còn ít nhất 1 admin đang hoạt động")
    changes = []
    if body.role is not None and body.role != user["role"]:
        changes.append(f"role {user['role']} -> {body.role}")
        user["role"] = body.role
    if body.disabled is not None and body.disabled != bool(user.get("disabled")):
        changes.append("khóa" if body.disabled else "mở khóa")
        user["disabled"] = body.disabled
    if body.password is not None:
        if (problem := password_problem(body.password, username)):
            raise HTTPException(400, problem)
        user.update(password_hash=hash_password(body.password), must_change=True)
        changes.append("đặt lại mật khẩu")
    if changes:
        user["updated_at"] = store.now_iso()
        users.put(user)
        sessions.drop_user(username)                 # quyền / mật khẩu đổi -> đăng nhập lại
        audit("user_updated", "success", s.username, client_ip(request), target=username, change="; ".join(changes))
    return public(user)
