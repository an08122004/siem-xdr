"""Kiểm thử giao diện hệ thống hợp nhất (SOC console + Grafana nhúng) bằng trình duyệt thật (Microsoft Edge).

    pip install playwright        # dùng Edge có sẵn trên máy (channel="msedge"), không cần tải trình duyệt
    python tools/ui_test.py [thư-mục-ảnh]

Tự tạo quản trị viên tạm `ui-admin` (xóa khi xong, cả bên Grafana), đi qua mọi trang, mở chi tiết alert / case,
bấm liên kết trong dashboard Grafana nhúng, đo lỗi JavaScript và chụp màn hình (máy tính + điện thoại).
Chạy từ thư mục siem-xdr khi stack đang chạy.
"""
import re
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding="utf-8")
BASE = "https://localhost:8000"
USER, PW = "ui-admin", "Giao-Dien-Kiem-Thu-7q2"
SHOTS = Path(sys.argv[1] if len(sys.argv) > 1 else "ui-shots")
SHOTS.mkdir(parents=True, exist_ok=True)
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"   {'✓' if ok else '✗'} {name}" + (f"  — {detail}" if detail else ""), flush=True)


def manager_py(code):
    return subprocess.run(["docker", "compose", "exec", "-T", "manager", "python", "-"], input=code,
                          capture_output=True, text=True, encoding="utf-8")


def setup_user():
    manager_py(f"""
from siem import store
from siem.manager import auth
auth.setup(store.connect(templates=False))
auth.users.put(auth.new_user({USER!r}, 'admin', {PW!r}, must_change=False))
""")


def drop_user():
    manager_py(f"""
import httpx
from siem import store, settings
es = store.connect(templates=False)
try:
    es.delete(index=settings.IDX_USERS, id={USER!r}, refresh='wait_for')
except Exception:
    pass
g = httpx.Client(base_url=settings.GRAFANA_URL + '/grafana', headers={{'X-WEBAUTH-USER': 'admin'}})
r = g.get('/api/users/lookup', params={{'loginOrEmail': {USER!r}}})
if r.status_code == 200:
    g.delete('/api/admin/users/%d' % r.json()['id'])
""")


def scroll_frame(page, iframe_sel, locator, tries=14, edge=False):
    """Grafana chỉ vẽ panel khi cuộn tới: cuộn trong khung dashboard tới khi thấy `locator`.
    Bánh xe cuộn thứ nằm dưới chuột. Chuột ở giữa khung (mặc định) cuộn bảng ở đó: dùng để tìm một dòng trong bảng
    (bảng chỉ vẽ các dòng đang hiện). `edge=True` đặt chuột ở lề trái 16px của dashboard (kiosk), ngoài mọi panel,
    để cuộn cả trang tới panel nằm dưới: chuột nằm trên bảng danh mục dài hàng trăm dòng thì mọi lần cuộn chỉ cuộn bảng
    đó (đã gặp 11/10/2026 khi có 155 đề xuất AI: không tới được bảng so sánh)."""
    frame = page.frame_locator(iframe_sel)
    box = page.locator(iframe_sel).bounding_box()
    page.mouse.move(box["x"] + (4 if edge else box["width"] / 2), box["y"] + box["height"] / 2)
    for _ in range(tries):
        if frame.locator(locator).count():
            return True
        page.mouse.wheel(0, 500)
        page.wait_for_timeout(1200)
    return frame.locator(locator).count() > 0


def shot(page, name):
    page.wait_for_timeout(350)                     # chờ hiệu ứng trượt của ngăn chi tiết
    page.screenshot(path=str(SHOTS / f"{name}.png"))


def main():
    setup_user()
    errors = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900}, locale="vi-VN")
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            # lỗi JavaScript của console / trang đăng nhập (không tính mã HTTP 401/404 khi tải tài nguyên, vd kiểm tra phiên)
            page.on("console", lambda m: m.type == "error" and "/grafana/" not in (m.location or {}).get("url", "")
                    and not m.text.startswith("Failed to load resource") and errors.append(f"console: {m.text}"))

            print("1. Đăng nhập qua liên kết sâu")
            page.goto(f"{BASE}/#/alerts")
            page.wait_for_url(re.compile(r"/login"))
            check("chưa đăng nhập -> trang đăng nhập, giữ #/alerts", "#/alerts" in page.url or "alerts" in page.url, page.url)
            page.fill("#u", USER)
            page.fill("#p", PW)
            page.click("#loginBtn")
            page.wait_for_url(re.compile(r"#/alerts"))
            page.wait_for_selector("#content table.list, #content .empty")
            check("đăng nhập xong quay về đúng #/alerts", page.url.endswith("#/alerts"), page.url)
            check("menu có đủ mục (admin thấy Tài khoản)", page.locator("#nav a").count() == 9)
            shot(page, "01-alerts")

            print("2. Cảnh báo: lọc, mở chi tiết")
            page.click("text=Tất cả")
            page.wait_for_timeout(600)
            rows = page.locator("#content tr.row")
            check("danh sách cảnh báo có dữ liệu", rows.count() > 0, f"{rows.count()} dòng")
            rows.first.click()
            page.wait_for_selector("#drawer:not([hidden]) h2")
            check("bấm dòng -> mở ngăn chi tiết, URL #/alerts/<id>", re.search(r"#/alerts/\w+", page.url) is not None)
            check("chi tiết có mục Xử lý, Phản ứng, SOAR, Sự kiện gốc",
                  all(page.locator(f"#drawer h3:text-is('{t}')").count() for t in ("Xử lý", "Phản ứng", "SOAR đã làm", "Sự kiện gốc")))
            shot(page, "02-alert-drawer")
            page.keyboard.press("Escape")
            page.wait_for_selector("#drawer", state="hidden")
            check("Esc đóng ngăn chi tiết", page.url.endswith("#/alerts"))
            page.fill("#tools input[type=search]", "zzz-khong-co-gi")
            page.wait_for_selector("#content .empty")
            check("tìm không ra -> trạng thái rỗng có hướng dẫn", "Bỏ lọc" in page.inner_text("#content"))
            page.fill("#tools input[type=search]", "")

            print("3. Case")
            page.goto(f"{BASE}/#/cases")
            page.wait_for_selector("#content table.list, #content .empty")
            if page.locator("#content tr.row").count():
                page.locator("#content tr.row").first.click()
                page.wait_for_selector("#drawer:not([hidden]) h2")
                check("mở case: có checklist và cảnh báo liên quan",
                      page.locator("#drawer .task").count() > 0 and page.locator("#drawer h3:text-is('Cảnh báo trong case')").count() == 1)
                shot(page, "03-case-drawer")
                if page.locator("#drawer .items li.link").count():
                    page.locator("#drawer .items li.link").first.click()
                    page.wait_for_url(re.compile(r"#/alerts/\w+"))
                    page.wait_for_function("!document.querySelector('#drawer').hidden && !document.querySelector('#drawer .prio')")
                    check("từ case bấm cảnh báo -> mở chi tiết cảnh báo", True)
            else:
                check("có case để mở", False, "chưa có case nào")

            print("4. Tổng quan: dashboard Grafana nhúng, liên kết sang console")
            page.goto(f"{BASE}/#/overview")
            frame = page.frame_locator("#frame-overview iframe")
            frame.locator("text=Tổng event").first.wait_for(timeout=120000)   # Grafana tải lần đầu có thể chậm
            page.wait_for_timeout(4000)
            check("dashboard Tổng quan hiện trong console", frame.locator("text=Alert theo mức độ").count() > 0)
            shot(page, "04-overview")
            # Grafana chỉ vẽ panel khi cuộn tới: cuộn trong khung dashboard tới bảng "Alert mới nhất"
            box = page.locator("#frame-overview iframe").bounding_box()
            page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            link = frame.locator("a[href*='/go/alert/']").first
            for _ in range(12):
                if link.count():
                    break
                page.mouse.wheel(0, 500)
                page.wait_for_timeout(1200)
            shot(page, "04b-overview-alert-table")
            if link.count():
                href = link.get_attribute("href")
                link.click()
                page.wait_for_url(re.compile(r"#/alerts/\w+"), timeout=15000)
                page.wait_for_selector("#drawer:not([hidden]) h2")
                check("bấm tên rule trong bảng Grafana -> mở chi tiết cảnh báo trong console", True, href)
                shot(page, "05-from-grafana")
            else:
                check("bảng Grafana có liên kết sang console", False, "không thấy liên kết /go/alert/ (chưa có alert trong 1 giờ?)")

            print("5. Điều tra thực thể")
            page.goto(f"{BASE}/#/investigate?q=" + "host.name%3A%22demo-web%22")
            frame = page.frame_locator("#frame-investigate iframe")
            frame.locator("text=Alert theo mức độ").first.wait_for(timeout=60000)
            page.wait_for_timeout(4000)
            check("dashboard Điều tra nhận bộ lọc từ console", 'host.name:"demo-web"' in page.input_value("#tools input[type=search]"))
            shot(page, "06-investigate")

            print("5b. Thư viện rule: tra cứu + so sánh với đề xuất AI")
            page.goto(f"{BASE}/#/rules")
            frame = page.frame_locator("#frame-rules iframe")
            frame.locator("text=Rule đang chạy").first.wait_for(timeout=120000)
            page.wait_for_timeout(3000)
            shot(page, "06b-rules")
            check("Thư viện rule hiện trong console, có ô lọc (Hiển thị, MITRE tactic, Tag, Trường log)",
                  all(frame.locator(f"text={t}").count() for t in ("Hiển thị", "MITRE tactic", "Trường log")))
            found = scroll_frame(page, "#frame-rules iframe", "text=WEB-001")
            check("bảng danh mục liệt kê rule (vd WEB-001)", found)
            page.goto(f"{BASE}/#/ai")
            page.wait_for_selector("#content p.sub")
            page.click("#tools button:text-is('Tất cả')")
            page.wait_for_timeout(800)
            if page.locator("#content tr.row").count():
                pid = page.locator("#content tr.row").first.get_attribute("data-id")
                page.locator("#content tr.row").first.click()
                page.click("text=So sánh với rule hiện có")
                page.wait_for_url(re.compile(r"#/rules\?proposal="))
                frame = page.frame_locator("#frame-rules iframe")
                frame.locator("text=Rule đang chạy").first.wait_for(timeout=60000)
                page.wait_for_timeout(2000)
                check("từ đề xuất AI bấm “So sánh” -> Grafana chọn đúng đề xuất đó", frame.locator(f"text={pid}").count() > 0, pid)
                ok = scroll_frame(page, "#frame-rules iframe", "text=Rule hiện có liên quan", edge=True)
                check("có bảng rule hiện có liên quan để so sánh", ok)
                shot(page, "06c-rules-compare")
            else:
                check("có đề xuất AI để so sánh", False, "chưa có đề xuất nào")

            print("6. Các trang còn lại")
            for view, sel in (("actions", "#content table.list, #content .empty"), ("agents", "#content table.list"),
                              ("ai", "#content p.sub"), ("users", "#content table.list")):
                page.goto(f"{BASE}/#/{view}")
                page.wait_for_selector(sel)
                check(f"trang {view} hiển thị", True)
                shot(page, f"07-{view}")
            page.goto(f"{BASE}/#/agents")
            page.wait_for_selector("#content table.list")
            page.click("text=Chặn IP…")
            page.fill("#content input[aria-label='IP cần chặn']", "khong-phai-ip")
            page.click("#content .inline-form button:text-is('Chặn')")
            page.wait_for_selector(".toast.err")
            check("form chặn IP báo lỗi IP sai ngay tại chỗ", "IP không hợp lệ" in page.inner_text("#toasts"))

            print("7. Điện thoại")
            mob = ctx.new_page()
            mob.set_viewport_size({"width": 390, "height": 844})
            mob.goto(f"{BASE}/#/alerts")
            mob.wait_for_selector("#content table.list, #content .empty")
            width = mob.evaluate("document.documentElement.scrollWidth")
            check("không tràn ngang trên màn hình 390px", width <= 400, f"scrollWidth={width}")
            shot(mob, "08-mobile-alerts")
            mob.close()

            print("8. Đăng xuất")
            page.goto(f"{BASE}/#/alerts")
            page.click("#me button:text-is('Đăng xuất')")
            page.wait_for_url(re.compile(r"/login\?reason=logged_out"))
            check("đăng xuất -> trang đăng nhập", True)
            check("không có lỗi JavaScript nào", not errors, "; ".join(errors[:5]))
            browser.close()
    finally:
        drop_user()
    print(f"\nTỔNG KẾT: {sum(RESULTS)}/{len(RESULTS)} đạt, ảnh trong {SHOTS}")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
