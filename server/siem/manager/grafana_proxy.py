"""Grafana đứng sau manager (https://<manager>/grafana/), dùng chung tài khoản, phiên và chính sách với SOC console.

Grafana chạy chế độ auth proxy (docker-compose.yml): tắt form đăng nhập và basic auth của chính Grafana, chỉ nhận
danh tính qua header X-WEBAUTH-USER gửi từ mạng nội bộ riêng manager <-> grafana (whitelist theo dải IP mạng đó,
container khác như máy web demo không giả được). Ở đây manager:
  - kiểm tra phiên console: chưa đăng nhập / hết phiên -> chuyển tới /login (khi mở trang) hoặc 401 (request API);
  - gửi X-WEBAUTH-USER = tên tài khoản, X-WEBAUTH-ROLE theo vai trò (admin -> Admin, lead -> Editor, analyst -> Viewer);
  - xóa mọi header X-WEBAUTH-* do trình duyệt gửi và cookie phiên console trước khi chuyển tiếp sang Grafana;
  - chỉ thao tác thật (mở trang, lưu, xem dashboard khác) mới gia hạn phiên. Dashboard tự làm mới 10 giây/lần
    (POST /api/ds/query) KHÔNG tính -> quên màn hình vẫn hết phiên sau CONSOLE_IDLE_MINUTES, giống console.
Đăng xuất trong Grafana: Grafana chuyển tới /logout của manager (GF_AUTH_SIGNOUT_REDIRECT_URL) -> thoát cả hai nơi.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from .. import settings
from . import auth

log = logging.getLogger("manager.grafana")
logging.getLogger("httpx").setLevel(logging.WARNING)            # không ghi log mỗi request được chuyển tiếp

# Editor cho mọi vai trò cần Explore / sửa dashboard (hunter săn mối đe dọa, detection sửa Thư viện rule, manager sửa
# dashboard SOC KPI); analyst chỉ xem
ROLE_MAP = {"admin": "Admin", "manager": "Editor", "lead": "Editor", "hunter": "Editor", "detection": "Editor",
            "analyst": "Viewer"}
PREFIX = "/grafana/"
# header không chuyển tiếp (hop-by-hop / do proxy tự tính lại)
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers",
        "transfer-encoding", "upgrade", "content-length"}
# request nền do dashboard tự gửi (tự làm mới, số liệu frontend) -> không phải thao tác của người dùng
_BACKGROUND_WRITES = ("api/ds/query", "api/frontend-metrics", "api/live/")
_USER_READS = ("api/dashboards/", "api/search")   # xem / tìm dashboard trong ứng dụng một trang của Grafana
# Grafana không có phiên riêng (GF_AUTH_PROXY_ENABLE_LOGIN_TOKEN=false). Cookie phiên Grafana còn sót trong trình duyệt
# (bản cũ mở Grafana ở localhost:3000 với form đăng nhập riêng; cookie không phân biệt cổng nên vẫn tới :8000) làm
# frontend Grafana 11 đọc grafana_session_expiry đã quá hạn -> gọi api/user/auth-tokens/rotate -> 401 -> tự tải lại
# trang -> lặp mãi: dashboard nhúng tải lại ~2 lần/giây, không bao giờ hiện xong (đã gặp 12/10/2026, 3270 lần / 30 phút).
# Không chuyển tiếp sang Grafana và xóa hẳn trong trình duyệt (mọi path Grafana có thể đã đặt).
_STALE_COOKIES = ("grafana_session", "grafana_session_expiry")
_STALE_PATHS = ("/", "/grafana", "/grafana/")

_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=settings.GRAFANA_URL, timeout=httpx.Timeout(60.0, connect=5.0))
    return _client


def set_client(c: httpx.AsyncClient | None) -> None:
    """Dùng cho test (MockTransport)."""
    global _client
    _client = c


async def close() -> None:
    if _client is not None:
        await _client.aclose()


FOLDER = "SIEM-XDR"                                    # = folder trong grafana/provisioning/dashboards
DEFAULT_PERMS = [{"role": "Viewer", "permission": 1}, {"role": "Editor", "permission": 2}]   # 1 = xem, 2 = sửa


async def ensure_folder_permissions(attempts: int = 60, delay: float = 5.0) -> bool:
    """Grafana 11 tạo thư mục provisioning không kèm quyền nào -> chỉ Admin thấy dashboard. Bản OSS không khai báo
    quyền thư mục bằng provisioning được, nên manager (thành phần Grafana tin qua auth proxy) gán quyền mặc định lúc
    khởi động: Viewer xem, Editor sửa. Chỉ gán khi thư mục chưa có quyền theo vai trò -> không ghi đè chỉnh sửa của admin."""
    hdr = {"x-webauth-user": "admin", "x-webauth-role": "Admin"}
    for i in range(attempts):
        try:
            r = await client().get(PREFIX + "api/folders", headers=hdr)
            folder = next((f for f in r.json() if f.get("title") == FOLDER), None) if r.status_code == 200 else None
            if folder:
                url = f"{PREFIX}api/folders/{folder['uid']}/permissions"
                current = (await client().get(url, headers=hdr)).json()
                if any(p.get("role") for p in current):
                    return True
                keep = [{k: p[k] for k in ("userId", "teamId", "permission") if p.get(k)} for p in current
                        if p.get("userId") or p.get("teamId")]
                r = await client().post(url, headers=hdr, json={"items": keep + DEFAULT_PERMS})
                if r.status_code == 200:
                    log.info("đã gán quyền mặc định cho thư mục Grafana %s (Viewer xem, Editor sửa)", FOLDER)
                    return True
                log.warning("gán quyền thư mục Grafana thất bại: %s %s", r.status_code, r.text[:200])
        except (httpx.HTTPError, ValueError) as e:
            if i == 0:
                log.info("chờ Grafana sẵn sàng để gán quyền thư mục: %s", e)
        await asyncio.sleep(delay)                     # Grafana chưa chạy / chưa provisioning xong
    return False


def is_navigation(request: Request) -> bool:
    return request.headers.get("sec-fetch-mode") == "navigate" or \
        (request.method == "GET" and "text/html" in request.headers.get("accept", ""))


def is_activity(request: Request, path: str) -> bool:
    """Request có phải thao tác của người dùng (được gia hạn phiên) không."""
    if is_navigation(request):
        return True
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        return not path.startswith(_BACKGROUND_WRITES)
    return path.startswith(_USER_READS)


router = APIRouter()


@router.api_route("/grafana", methods=["GET", "HEAD"], include_in_schema=False)
async def grafana_root() -> Response:
    return RedirectResponse(PREFIX, status_code=308)


@router.api_route("/grafana/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                  include_in_schema=False)
async def grafana(path: str, request: Request) -> Response:
    token = request.cookies.get(auth.COOKIE)
    s = auth.sessions.get(token, touch=is_activity(request, path)) if token else None
    target = PREFIX + path + (f"?{request.url.query}" if request.url.query else "")
    if not s or s.must_change:
        if is_navigation(request):
            reason = "change=1&" if s else ("reason=expired&" if token else "")
            nxt = PREFIX if path.startswith("login") else target      # trang login riêng của Grafana đã tắt
            return RedirectResponse(f"/login?{reason}next={quote(nxt, safe='')}", status_code=303)
        return JSONResponse({"detail": "chưa đăng nhập hoặc phiên đã hết hạn"}, status_code=401)

    headers = [(k, v) for k, v in request.headers.items()
               if k.lower() not in _HOP and k.lower() != "cookie" and not k.lower().startswith("x-webauth-")]
    jar = [(c.split("=", 1)[0], c) for c in (x.strip() for x in request.headers.get("cookie", "").split(";")) if c]
    stale = sorted({name for name, _ in jar if name in _STALE_COOKIES})
    # cookie phiên console và cookie phiên Grafana cũ không đi sang Grafana
    cookie = "; ".join(c for name, c in jar if name != auth.COOKIE and name not in _STALE_COOKIES)
    if cookie:
        headers.append(("cookie", cookie))
    headers += [("x-webauth-user", s.username), ("x-webauth-name", s.username),
                ("x-webauth-role", ROLE_MAP.get(s.role, "Viewer")),
                ("x-forwarded-for", auth.client_ip(request)), ("x-forwarded-proto", "https")]
    upstream = client().build_request(request.method, target, headers=headers, content=await request.body())
    try:
        r = await client().send(upstream, stream=True)
    except httpx.HTTPError as e:
        log.warning("không chuyển tiếp được tới Grafana: %s", e)
        return JSONResponse({"detail": "Grafana không phản hồi"}, status_code=502)
    resp = StreamingResponse(r.aiter_raw(), status_code=r.status_code, background=BackgroundTask(r.aclose))
    # giữ nguyên header của Grafana (kể cả nhiều Set-Cookie), bỏ header hop-by-hop và cookie phiên Grafana
    resp.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in r.headers.multi_items()
                        if k.lower() not in _HOP and not (k.lower() == "set-cookie" and
                                                          v.split("=", 1)[0].strip() in _STALE_COOKIES)]
    resp.raw_headers += [(b"set-cookie", f"{name}=; Path={p}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT".encode())
                         for name in stale for p in _STALE_PATHS]
    return resp
