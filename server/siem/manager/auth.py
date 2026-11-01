"""Đăng nhập SOC console bằng tài khoản riêng từng người (thay cho API key dùng chung).

- Mật khẩu băm scrypt (salt ngẫu nhiên riêng từng tài khoản), lưu ở index Elasticsearch `console-users`. Index nằm
  NGOÀI `siem-*` nên Grafana và tài khoản chỉ đọc `analyst` (role siem_reader) không đọc được hash.
- Phiên: token ngẫu nhiên 256 bit trong cookie HttpOnly + Secure + SameSite=Strict; phía server chỉ giữ SHA-256 của
  token, trong bộ nhớ manager và index `console-sessions` (manager khởi động lại không đăng xuất ai). Hết hạn sau CONSOLE_IDLE_MINUTES
  không thao tác (request tự làm mới của console gửi header X-Auto-Refresh, không tính là thao tác) và tối đa
  CONSOLE_SESSION_HOURS kể từ lúc đăng nhập.
- Chống CSRF: cookie SameSite=Strict, và request thay đổi dữ liệu phải có header X-Requested-With (trang web khác
  không gửi được header tự đặt vì manager không bật CORS).
- Chống dò mật khẩu: sai CONSOLE_MAX_FAILURES lần trong 15 phút (theo tên đăng nhập hoặc theo IP) -> khóa 15 phút.
  Tên không tồn tại vẫn tốn đúng một lần tính scrypt -> không dò được tên qua thời gian phản hồi.
- Vai trò theo cơ cấu SOC (SOC-OPERATIONS.md mục 1): analyst (Tier 1), lead (Tier 2 IR), hunter (Tier 3), detection
  (Detection Engineer), manager (SOC Manager), admin. Quyền tính theo năng lực (PERMISSIONS), không theo thang:
  Detection Engineer duyệt rule nhưng không cô lập máy; người xử lý cảnh báo không tự duyệt rule mình dùng.
- Tự đăng ký từ trang đăng nhập (kèm họ tên, ngày sinh, quê quán, số điện thoại, chức vụ): tài khoản chờ duyệt, bị
  khóa tới khi admin duyệt và gán vai trò; admin từ chối thì yêu cầu bị xóa. Admin xem / thu hồi được mọi phiên.
- Người thực hiện mọi thao tác lấy từ phiên (không tự khai) -> lịch sử case / duyệt AI đáng tin, và quy định
  "ngoại lệ AI cần 2 người KHÁC NHAU duyệt" có hiệu lực thật.
- Đăng nhập / đăng xuất / đổi mật khẩu / quản lý tài khoản được ghi thành dòng JSON (volume console_audit), wazuh-manager
  đọc rồi đi cùng đường Wazuh -> Kafka thành event của chính SIEM (event_type console_auth): lưu trong siem-events-*, hiện trên Grafana (Phiên đăng nhập), rule AUTH-001 áp dụng được.
- Xác thực 2 lớp TOTP (RFC 6238: HMAC-SHA1, 30 giây, 6 số; Google Authenticator, Microsoft Authenticator...). Bật
  tự nguyện, hoặc bắt buộc với vai trò trong CONSOLE_MFA_REQUIRED_ROLES: chưa bật thì phiên chỉ dùng được để bật MFA.
  Mỗi mã chỉ dùng được một lần (lưu bước thời gian đã dùng), nhập sai mã tính như sai mật khẩu. Khóa bí mật TOTP nằm
  trong console-users (ngoài siem-*, chỉ manager đọc được), không bao giờ trả ra API sau khi đã bật.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import sys
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from logging.handlers import RotatingFileHandler
from time import monotonic as time_monotonic
from typing import Any, Callable

from elasticsearch import ConflictError, NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from .. import settings, store

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
    "admin": frozenset({"triage", "contain", "hunt", "rules", "declare", "users"}),   # Platform Engineer
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
PHONE_PATTERN = r"^(0|\+84)[0-9]{9,10}$"
# thông tin cá nhân của tài khoản (chỉ nằm trong console-users: Grafana / analyst không đọc được, không ghi vào nhật ký)
PROFILE = {"full_name": "họ và tên", "birth_date": "ngày sinh", "hometown": "quê quán", "phone": "số điện thoại",
           "position": "chức vụ"}


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


# --------------------------------------------------------------------------- TOTP (RFC 6238)
TOTP_STEP, TOTP_DIGITS, TOTP_WINDOW = 30, 6, 1       # chấp nhận lệch ±1 bước (đồng hồ điện thoại lệch tới 30 giây)
MFA_ISSUER = "SIEM-XDR"


def totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_match(secret: str, code: str, last_step: int = -1) -> int | None:
    """Bước thời gian khớp với mã (để ghi lại, chống dùng lại), None nếu sai / đã dùng."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = int(time.time() // TOTP_STEP)
    for step in range(now - TOTP_WINDOW, now + TOTP_WINDOW + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, username: str) -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(MFA_ISSUER)}:{quote(username)}?secret={secret}&issuer={quote(MFA_ISSUER)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def mfa_required(role: str) -> bool:
    return role in settings.CONSOLE_MFA_REQUIRED_ROLES


def mfa_enabled(user: dict[str, Any]) -> bool:
    return bool((user.get("mfa") or {}).get("enabled") and (user.get("mfa") or {}).get("secret"))


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
    """Tài khoản trả ra API: không hash mật khẩu, không khóa bí mật TOTP."""
    out = {k: v for k, v in user.items() if k not in ("password_hash", "mfa")}
    out["mfa_enabled"] = mfa_enabled(user)
    return out


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

    def delete(self, username: str) -> None:
        try:
            self.es.delete(index=settings.IDX_USERS, id=username, refresh="wait_for")
        except NotFoundError:
            pass


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

    def delete(self, username):
        self.users.pop(username, None)


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
    must_mfa: bool = False         # vai trò bắt buộc MFA mà chưa bật: phiên chỉ dùng để bật MFA


class SessionStore:
    """Phiên trong Elasticsearch (index console-sessions, id = SHA-256 của token) để manager khởi động lại (deploy,
    Docker restart) không đăng xuất mọi người."""

    def __init__(self, es):
        self.es = es

    def save(self, s: Session) -> None:
        self.es.index(index=settings.IDX_SESSIONS, id=s.key, document=asdict(s))

    def load(self, key: str) -> Session | None:
        try:
            return Session(**self.es.get(index=settings.IDX_SESSIONS, id=key)["_source"])
        except NotFoundError:
            return None

    def all(self) -> list[Session]:
        try:
            res = self.es.search(index=settings.IDX_SESSIONS, size=1000, query={"match_all": {}})
        except NotFoundError:
            return []
        return [Session(**h["_source"]) for h in res["hits"]["hits"]]

    def _delete(self, query: dict[str, Any]) -> None:
        # không refresh (cần quyền maintenance); delete_by_query tìm gần thời gian thực -> phiên vừa ghi < 1 giây có thể
        # sót: phiên đang có trong bộ nhớ luôn được xóa theo id trước (Sessions.drop_user)
        try:
            self.es.delete_by_query(index=settings.IDX_SESSIONS, query=query, conflicts="proceed")
        except NotFoundError:
            pass

    def delete(self, key: str) -> None:
        try:
            self.es.delete(index=settings.IDX_SESSIONS, id=key)     # theo id: thời gian thực, không phụ thuộc refresh
        except NotFoundError:
            pass

    def delete_user(self, username: str, keep: str | None = None) -> None:
        self._delete({"bool": {"filter": [{"term": {"username": username}}],
                               "must_not": [{"ids": {"values": [keep]}}] if keep else []}})

    def purge(self, active_before: float, created_before: float) -> None:
        self._delete({"bool": {"should": [{"range": {"last_active": {"lt": active_before}}},
                                          {"range": {"created": {"lt": created_before}}}], "minimum_should_match": 1}})


class Sessions:
    """Bộ nhớ là chính; `store` (nếu có) giữ bản sao để nạp lại phiên sau khi manager khởi động lại. Lỗi của store chỉ
    ghi log: đăng nhập vẫn chạy bằng bộ nhớ, chỉ không giữ được phiên qua lần khởi động lại."""
    SAVE_EVERY = 60     # giây: last_active ghi xuống store tối đa 1 lần / phút / phiên, không phải mỗi request

    def __init__(self, store: SessionStore | None = None):
        self._d: dict[str, Session] = {}
        self._saved: dict[str, float] = {}       # key -> lúc ghi xuống store lần cuối
        self._lock = threading.Lock()
        self.store = store

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _expired(s: Session, now: float) -> bool:
        return now - s.last_active > settings.CONSOLE_IDLE_MINUTES * 60 or \
            now - s.created > settings.CONSOLE_SESSION_HOURS * 3600

    def _persist(self, method: str, *args: Any) -> Any:
        if self.store is None:
            return None
        try:
            return getattr(self.store, method)(*args)
        except Exception as e:  # noqa: BLE001
            log.warning("kho phiên đăng nhập lỗi (%s): %s", method, e)
            return None

    def create(self, user: dict[str, Any], ip: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = time.time()
        s = Session(self._key(token), user["username"], user["role"], ip, now, now, bool(user.get("must_change")),
                    mfa_required(user["role"]) and not mfa_enabled(user))
        with self._lock:
            # dọn phiên bỏ dở (đóng trình duyệt không đăng xuất) để bộ nhớ không phình theo thời gian
            for k in [k for k, x in self._d.items() if self._expired(x, now)]:
                del self._d[k]
                self._saved.pop(k, None)
            self._d[s.key] = s
        self._persist("purge", now - settings.CONSOLE_IDLE_MINUTES * 60, now - settings.CONSOLE_SESSION_HOURS * 3600)
        self.save(s)
        return token, s

    def save(self, s: Session) -> None:
        """Ghi phiên xuống store (gọi thêm khi đổi thuộc tính phiên, vd hết bị buộc đổi mật khẩu)."""
        self._saved[s.key] = time.time()
        self._persist("save", s)

    def __len__(self) -> int:
        return len(self._d)

    def get(self, token: str, touch: bool = True) -> Session | None:
        now, key = time.time(), self._key(token)
        with self._lock:
            s = self._d.get(key)
        if s is None:
            s = self._persist("load", key)                # manager vừa khởi động lại: phiên còn trong store
            if s is None:
                return None
            with self._lock:
                s = self._d.setdefault(key, s)
            self._saved.setdefault(key, s.last_active)
        with self._lock:
            expired = self._expired(s, now)
            if expired:
                self._d.pop(key, None)
                self._saved.pop(key, None)
            elif touch:
                s.last_active = now
        if expired:
            self._persist("delete", key)
            return None
        # last_active trong store chậm tối đa SAVE_EVERY giây: sau khi khởi động lại, phiên có thể hết hạn sớm chừng đó
        if touch and now - self._saved.get(key, 0) >= self.SAVE_EVERY:
            self.save(s)
        return s

    def active(self) -> list[Session]:
        """Mọi phiên còn hạn, kể cả phiên chưa nạp lại vào bộ nhớ sau khi manager khởi động lại; thao tác gần nhất trước."""
        now, found = time.time(), {s.key: s for s in (self._persist("all") or [])}
        with self._lock:
            found.update(self._d)                         # bộ nhớ mới hơn: last_active trong store chậm tới SAVE_EVERY giây
        return sorted((s for s in found.values() if not self._expired(s, now)), key=lambda s: -s.last_active)

    def drop(self, token: str) -> None:
        self.drop_key(self._key(token))

    def drop_key(self, key: str) -> None:
        self._persist("delete", key)                      # xóa ở store trước: request song song không nạp lại được
        with self._lock:
            self._d.pop(key, None)
            self._saved.pop(key, None)

    def drop_user(self, username: str, keep: Session | None = None) -> None:
        with self._lock:
            keys = [k for k, s in self._d.items() if s.username == username and s is not keep]
        for k in keys:
            self._persist("delete", k)
        self._persist("delete_user", username, keep.key if keep else None)   # phiên chưa nạp vào bộ nhớ từ lần trước
        with self._lock:
            for k in keys:
                self._d.pop(k, None)
                self._saved.pop(k, None)


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
AUDIT_MAX_BYTES = 20 * 1024 * 1024      # xoay vòng 20 MB x 5 file; wazuh-manager theo dõi inode nên đọc tiếp file mới


class Audit:
    """Ghi sự kiện đăng nhập / quản lý tài khoản thành MỘT dòng JSON vào CONSOLE_AUDIT_FILE (volume console_audit);
    wazuh-manager đọc file bằng <localfile> nên nhật ký console cũng đi qua Wazuh (best effort: lỗi ghi file chỉ log cảnh
    báo, tối đa mỗi phút một lần, không chặn đăng nhập)."""

    WARN_EVERY = 60.0

    def __init__(self):
        self._lock = threading.Lock()
        self._path: str | None = None
        self._handler: logging.Handler | None = None
        self._last_warn: float | None = None

    def _warn(self, err: Any) -> None:
        now = time_monotonic()
        if self._last_warn is None or now - self._last_warn >= self.WARN_EVERY:
            self._last_warn = now
            log.warning("không ghi được nhật ký console vào %s: %s", settings.CONSOLE_AUDIT_FILE, err)

    def _logger(self) -> logging.Logger:
        """Tạo handler lúc cần (thư mục volume có thể chưa sẵn lúc manager khởi động); lỗi mở file thì thử lại lần gọi sau."""
        lg = logging.getLogger("siem.console_audit")
        if self._handler is None or self._path != settings.CONSOLE_AUDIT_FILE:
            for h in list(lg.handlers):
                lg.removeHandler(h)
                h.close()
            self._handler = None
            h = RotatingFileHandler(settings.CONSOLE_AUDIT_FILE, maxBytes=AUDIT_MAX_BYTES, backupCount=5, encoding="utf-8")
            h.setFormatter(logging.Formatter("%(message)s"))
            h.handleError = lambda record: self._warn(sys.exc_info()[1])    # đĩa đầy, mất quyền giữa chừng
            lg.addHandler(h)
            lg.setLevel(logging.INFO)
            lg.propagate = False
            self._handler, self._path = h, settings.CONSOLE_AUDIT_FILE
        return lg

    def __call__(self, action: str, outcome: str, user: str, ip: str, **extra: Any) -> None:
        rec = {"timestamp": store.now_iso(), "event_type": "console_auth", "action": action, "outcome": outcome,
               "user": user, "ip": ip, **{k: v for k, v in extra.items() if v is not None}}
        log.info("console %s %s: user=%s ip=%s %s", action, outcome, user, ip, extra or "")
        try:
            with self._lock:
                self._logger().info(json.dumps(rec, default=str))    # json.dumps thoát xuống dòng -> mỗi sự kiện đúng một dòng
        except Exception as e:  # noqa: BLE001
            self._warn(e)


users: UserStore | None = None
sessions = Sessions()
throttle = Throttle()
audit: Callable[..., None] = Audit()


def setup(es) -> None:
    """Gọi khi manager khởi động: gắn kho tài khoản, kho phiên và tạo tài khoản admin đầu tiên nếu chưa có ai."""
    global users
    users = UserStore(es)
    sessions.store = SessionStore(es)
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
    if s.must_mfa:
        raise HTTPException(403, "phải bật xác thực 2 lớp trước khi dùng console (vai trò của bạn bắt buộc MFA)")
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
    otp: str | None = Field(None, max_length=16)


class PasswordBody(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=1, max_length=256)


class ProfileFields(BaseModel):
    full_name: str | None = Field(None, max_length=80)
    birth_date: date | None = None
    hometown: str | None = Field(None, max_length=80)
    phone: str | None = Field(None, pattern=PHONE_PATTERN)
    position: str | None = Field(None, max_length=60)

    def profile(self) -> dict[str, str]:
        """Các trường đã điền (chữ bỏ khoảng trắng thừa, ngày dạng YYYY-MM-DD)."""
        out = {k: v.isoformat() if isinstance(v, date) else " ".join(str(v).split()) for k in PROFILE if (v := getattr(self, k))}
        return {k: v for k, v in out.items() if v}

    def problem(self, required: bool) -> str | None:
        p = self.profile()
        if required and (missing := [label for k, label in PROFILE.items() if k not in p]):
            return "chưa nhập " + ", ".join(missing)
        if any(len(p.get(k, "xx")) < 2 for k in ("full_name", "hometown", "position")):
            return "họ tên, quê quán, chức vụ tối thiểu 2 ký tự"
        if self.birth_date:
            today = date.today()
            age = today.year - self.birth_date.year - ((today.month, today.day) < (self.birth_date.month, self.birth_date.day))
            if not 16 <= age <= 100:
                return "ngày sinh không hợp lệ (tuổi từ 16 đến 100)"
        return None


class NewUser(ProfileFields):
    username: str = Field(pattern=USERNAME_PATTERN)
    role: str = Field(pattern=ROLE_PATTERN)
    password: str = Field(min_length=1, max_length=256)


class Registration(ProfileFields):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=256)


class Approval(BaseModel):
    role: str = Field(pattern=ROLE_PATTERN)


class UserUpdate(BaseModel):
    role: str | None = Field(None, pattern=ROLE_PATTERN)
    disabled: bool | None = None
    password: str | None = Field(None, min_length=1, max_length=256)   # đặt lại -> buộc đổi ở lần đăng nhập sau
    mfa_reset: bool | None = None          # mất điện thoại: xóa MFA, người dùng bật lại ở lần đăng nhập sau


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=256)


def _me(s: Session) -> dict[str, Any]:
    user = users.get(s.username) if users else None
    return {"username": s.username, "role": s.role, "role_label": ROLE_LABELS.get(s.role, s.role),
            "permissions": sorted(PERMISSIONS.get(s.role, ())), "must_change": s.must_change, "must_mfa": s.must_mfa,
            "mfa_enabled": mfa_enabled(user or {}), "mfa_required": mfa_required(s.role),
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
    if valid and user and user.get("pending"):          # đúng mật khẩu mới báo: không lộ tài khoản chờ duyệt cho người đoán
        audit("login", "failure", username, ip, reason="pending")
        raise HTTPException(403, "tài khoản đang chờ quản trị viên duyệt")
    if not (valid and user and not user.get("disabled")):
        locked = throttle.failure(*keys)
        audit("login", "failure", username, ip, reason="locked" if locked else "bad_credentials")
        raise HTTPException(401, "sai tên đăng nhập hoặc mật khẩu")
    if mfa_enabled(user):
        if not body.otp:          # mật khẩu đúng: trang đăng nhập hỏi tiếp mã 6 số (không tính là sai)
            raise HTTPException(401, {"message": "nhập mã xác thực 6 số trong ứng dụng xác thực", "mfa": "required"})
        step = totp_match(user["mfa"]["secret"], body.otp, int(user["mfa"].get("last_step", -1)))
        if step is None:
            locked = throttle.failure(*keys)
            audit("login", "failure", username, ip, reason="locked" if locked else "bad_otp")
            raise HTTPException(401, {"message": "mã xác thực không đúng hoặc đã dùng", "mfa": "invalid"})
        user["mfa"]["last_step"] = step
    throttle.success(keys[0])
    token, s = sessions.create(user, ip)
    user["last_login"] = store.now_iso()
    users.put(user)
    response.set_cookie(COOKIE, token, httponly=True, secure=True, samesite="strict", path="/",
                        max_age=settings.CONSOLE_SESSION_HOURS * 3600)
    audit("login", "success", username, ip, role=user["role"])
    return _me(s)


@router.post("/api/v1/auth/register")
def register(body: Registration, request: Request) -> dict[str, Any]:
    """Tự đăng ký từ trang đăng nhập: tài khoản ở trạng thái chờ duyệt (bị khóa) tới khi admin duyệt và gán vai trò."""
    _check_csrf(request)
    ip, key = client_ip(request), f"register:{client_ip(request)}"
    if (wait := throttle.wait(key)):
        raise HTTPException(429, f"gửi quá nhiều yêu cầu đăng ký, thử lại sau {int(wait // 60) + 1} phút")
    if (problem := body.problem(required=True) or password_problem(body.password, body.username)):
        raise HTTPException(400, problem)
    throttle.failure(key)                  # không phải lỗi: dùng bộ đếm để giới hạn số yêu cầu mỗi IP trong 15 phút
    user = new_user(body.username, "analyst", body.password, must_change=False) | body.profile() | {
        "disabled": True, "pending": True, "requested_ip": ip}
    if not users.create(user):
        raise HTTPException(409, f"tên đăng nhập {body.username} đã có người dùng")
    audit("register", "success", body.username, ip)
    return {"ok": True, "username": body.username, "pending": True}


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
    sessions.save(s)
    audit("password_changed", "success", s.username, ip, role=s.role)
    return _me(s)


@router.post("/api/v1/auth/mfa/setup")
def mfa_setup(request: Request, s: Session = Depends(session)) -> dict[str, Any]:
    """Tạo khóa bí mật TOTP mới (chờ xác nhận bằng một mã đúng). Bật rồi thì phải tắt / nhờ admin đặt lại trước."""
    if s.must_change:
        raise HTTPException(403, "phải đổi mật khẩu trước")
    user = users.get(s.username)
    if mfa_enabled(user):
        raise HTTPException(409, "tài khoản đã bật xác thực 2 lớp")
    secret = totp_secret()
    user["mfa"] = {**(user.get("mfa") or {}), "enabled": False, "secret": None, "pending": secret}
    users.put(user)
    return {"secret": secret, "otpauth_uri": otpauth_uri(secret, s.username), "issuer": MFA_ISSUER,
            "digits": TOTP_DIGITS, "period": TOTP_STEP}


@router.post("/api/v1/auth/mfa/enable")
def mfa_enable(body: MfaCode, request: Request, s: Session = Depends(session)) -> dict[str, Any]:
    user, ip = users.get(s.username), client_ip(request)
    pending = (user.get("mfa") or {}).get("pending")
    if not pending:
        raise HTTPException(400, "chưa tạo khóa xác thực, bấm thiết lập lại")
    step = totp_match(pending, body.code)
    if step is None:
        throttle.failure(f"user:{s.username}", f"ip:{ip}")
        audit("mfa_enabled", "failure", s.username, ip, reason="bad_otp")
        raise HTTPException(400, "mã không đúng: kiểm tra giờ trên điện thoại và nhập mã đang hiện")
    user["mfa"] = {"enabled": True, "secret": pending, "pending": None, "last_step": step, "enabled_at": store.now_iso()}
    user["updated_at"] = store.now_iso()
    users.put(user)
    sessions.drop_user(s.username, keep=s)            # phiên cũ (chưa qua MFA) phải đăng nhập lại
    s.must_mfa = False
    sessions.save(s)                                  # kho phiên: khởi động lại manager không đòi bật MFA lần nữa
    audit("mfa_enabled", "success", s.username, ip, role=s.role)
    return _me(s)


@router.post("/api/v1/auth/mfa/disable")
def mfa_disable(body: MfaDisable, request: Request, s: Session = Depends(current_user)) -> dict[str, Any]:
    if mfa_required(s.role):
        raise HTTPException(400, "vai trò của bạn bắt buộc xác thực 2 lớp, không tắt được")
    user, ip = users.get(s.username), client_ip(request)
    if not verify_password(body.password, user["password_hash"]):
        throttle.failure(f"user:{s.username}", f"ip:{ip}")
        raise HTTPException(400, "mật khẩu không đúng")
    user["mfa"] = {"enabled": False, "secret": None, "pending": None}
    users.put(user)
    audit("mfa_disabled", "success", s.username, ip, role=s.role)
    return _me(s)


@router.get("/api/v1/users")
def list_users(s: Session = Depends(require_perm("users"))) -> list[dict[str, Any]]:
    return [public(u) for u in users.list()]


@router.post("/api/v1/users")
def create_user(body: NewUser, request: Request, s: Session = Depends(require_perm("users"))) -> dict[str, Any]:
    if (problem := body.problem(required=False) or password_problem(body.password, body.username)):
        raise HTTPException(400, problem)
    user = new_user(body.username, body.role, body.password, must_change=True) | body.profile()
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
    if user.get("pending"):
        raise HTTPException(400, "tài khoản đang chờ duyệt: duyệt hoặc từ chối yêu cầu đăng ký trước")
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
    if body.mfa_reset and mfa_enabled(user):
        user["mfa"] = {"enabled": False, "secret": None, "pending": None}
        changes.append("đặt lại xác thực 2 lớp")
    if changes:
        user["updated_at"] = store.now_iso()
        users.put(user)
        sessions.drop_user(username)                 # quyền / mật khẩu đổi -> đăng nhập lại
        audit("user_updated", "success", s.username, client_ip(request), target=username, change="; ".join(changes))
    return public(user)


def _pending(username: str) -> dict[str, Any]:
    user = users.get(username)
    if not user or not user.get("pending"):
        raise HTTPException(404, f"không có yêu cầu đăng ký chờ duyệt của {username}")
    return user


@router.post("/api/v1/users/{username}/approve")
def approve_user(username: str, body: Approval, request: Request,
                 s: Session = Depends(require_perm("users"))) -> dict[str, Any]:
    user, now = _pending(username), store.now_iso()
    user.update(pending=False, disabled=False, role=body.role, approved_by=s.username, approved_at=now, updated_at=now)
    users.put(user)
    audit("user_approved", "success", s.username, client_ip(request), target=username, target_role=body.role)
    return public(user)


@router.delete("/api/v1/users/{username}")
def reject_user(username: str, request: Request, s: Session = Depends(require_perm("users"))) -> dict[str, bool]:
    """Chỉ xóa yêu cầu đăng ký chưa duyệt; tài khoản đã dùng thì khóa (giữ nguyên ai đã làm gì trong nhật ký)."""
    _pending(username)
    users.delete(username)
    audit("user_rejected", "success", s.username, client_ip(request), target=username)
    return {"ok": True}


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


@router.get("/api/v1/admin/sessions")
def list_sessions(s: Session = Depends(require_perm("users"))) -> list[dict[str, Any]]:
    """Phiên đăng nhập đang còn hạn của mọi tài khoản (id = SHA-256 của token, không dùng làm cookie được).
    Phiên của tài khoản không còn / đã khóa mà không qua API (vd xóa thẳng trong Elasticsearch) bị thu hồi luôn."""
    known = {u["username"]: u for u in users.list()}
    out = []
    for x in sessions.active():
        if x.username not in known or known[x.username].get("disabled"):
            sessions.drop_key(x.key)
            continue
        out.append({"id": x.key, "username": x.username, "role": x.role, "ip": x.ip, "created": _iso(x.created),
                    "last_active": _iso(x.last_active), "must_change": x.must_change, "current": x.key == s.key})
    return out


@router.delete("/api/v1/admin/sessions/{key}")
def revoke_session(key: str, request: Request, s: Session = Depends(require_perm("users"))) -> dict[str, bool]:
    target = next((x for x in sessions.active() if x.key == key), None)
    if not target:
        raise HTTPException(404, "phiên không còn tồn tại")
    if target.key == s.key:
        raise HTTPException(400, "đây là phiên của chính bạn: dùng Đăng xuất")
    sessions.drop_key(key)
    audit("session_revoked", "success", s.username, client_ip(request), target=target.username, reason=target.ip)
    return {"ok": True}
