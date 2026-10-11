"""SOAR <-> Wazuh: ra lệnh phản ứng trên agent qua Wazuh API và đồng bộ danh sách agent.

Luồng một lệnh (block_ip, kill_process...):
  SOAR / analyst tạo action (siem-actions, status pending)
    -> Responder.dispatch(): PUT /active-response?agents_list=<id> {"command": "!siem-xdr", "arguments": [...]}
       (status sent; Wazuh từ chối, vd agent mất kết nối -> failed)
    -> wazuh-manager chuyển xuống agent, agent chạy script active-response/bin/siem-xdr (cài sẵn, root)
    -> script ghi 1 dòng kết quả vào active-responses.log, agent gửi dòng đó về như mọi log khác
    -> analyzer chuẩn hóa thành event.action=response_result (siem-events-*)
    -> Responder.collect_results(): khớp action id + agent -> success / failed
Active response của Wazuh là "bắn rồi quên" (API chỉ báo đã gửi), nên kết quả thật lấy từ log do chính agent gửi về.
Lệnh `sent` quá 10 phút không có kết quả -> timeout (Soar.housekeeping).

Wazuh API dùng user `siem-soar` chỉ có quyền active-response:command và agent:read (wazuh/manager/entrypoint).
"""
from __future__ import annotations

import base64
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import settings, store

log = logging.getLogger("soar.wazuh")

_IP = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
PROC_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")     # tên tiến trình được phép đưa xuống script trên agent


class WazuhError(RuntimeError):
    pass


class WazuhAPI:
    """Client tối giản cho Wazuh API (JWT, tự lấy lại token khi hết hạn). Chỉ dùng thư viện chuẩn."""

    def __init__(self, url: str, user: str, password: str, ca_file: str = "", timeout: int = 10):
        self.url = url.rstrip("/")
        self.user, self.password = user, password
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file or None)
        self._token: str | None = None
        self._token_at = 0.0

    def _open(self, req: urllib.request.Request) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            raise WazuhError(f"HTTP {e.code} {req.full_url}: {body}") from e
        except (urllib.error.URLError, OSError) as e:
            raise WazuhError(f"không kết nối được Wazuh API {self.url}: {e}") from e

    def token(self) -> str:
        if self._token and time.time() - self._token_at < 600:     # token mặc định sống 900 giây
            return self._token
        basic = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"{self.url}/security/user/authenticate", method="POST",
                                     headers={"Authorization": f"Basic {basic}"})
        self._token = self._open(req)["data"]["token"]
        self._token_at = time.time()
        return self._token

    def request(self, method: str, path: str, body: dict | None = None) -> dict[str, Any]:
        for attempt in (0, 1):
            req = urllib.request.Request(
                f"{self.url}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                headers={"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"})
            try:
                return self._open(req)
            except WazuhError as e:
                if attempt == 0 and "HTTP 401" in str(e):   # token bị thu hồi / hết hạn sớm -> lấy lại 1 lần
                    self._token = None
                    continue
                raise
        raise AssertionError("unreachable")

    def agents(self) -> list[dict[str, Any]]:
        res = self.request("GET", "/agents?limit=500&select=id,name,ip,status,version,lastKeepAlive,os.name,"
                                  "os.version,os.platform,group")
        return res.get("data", {}).get("affected_items", [])

    def active_response(self, agent_id: str, arguments: list[str], script: str) -> dict[str, Any]:
        """`!<script>`: chạy thẳng file active-response/bin/<script> đã cài sẵn trên agent (không cần khai báo
        <command> trong ossec.conf của manager)."""
        body = {"command": f"!{script}", "arguments": arguments}
        return self.request("PUT", f"/active-response?agents_list={agent_id}", body)


def ar_script(platform: str | None) -> str:
    """Windows chỉ chạy được file có đuôi (.cmd gọi PowerShell), Linux dùng script sh không đuôi."""
    return f"{settings.WAZUH_AR_SCRIPT}.cmd" if (platform or "").lower() == "windows" else settings.WAZUH_AR_SCRIPT


def ar_arguments(action: dict[str, Any]) -> list[str]:
    """Tham số cho script siem-xdr: [loại, đích, action_id] và, với kill theo PID của SOAR, [tên tiến trình mong đợi]
    (script không kill nếu PID đã thuộc tiến trình khác; script cũ chỉ đọc 3 tham số đầu nên vẫn chạy được).
    Kiểm tra chặt ở đây VÀ trong script trên agent."""
    typ, params = action["type"], action.get("params") or {}
    extra: list[str] = []
    if typ in ("block_ip", "unblock_ip"):
        target = str(params.get("ip") or "")
        if not _IP.match(target):
            raise ValueError(f"IP không hợp lệ: {target!r}")
    elif typ == "kill_process":
        target = str(params.get("pid") or params.get("name") or "")
        if not (target.isdigit() or PROC_NAME.match(target)):
            raise ValueError(f"PID / tên tiến trình không hợp lệ: {target!r}")
        if expect := params.get("expect"):
            if not (target.isdigit() and PROC_NAME.match(str(expect))):
                raise ValueError(f"tên tiến trình mong đợi không hợp lệ: {expect!r}")
            extra = [str(expect)]
    elif typ in ("isolate_host", "unisolate_host"):
        target = "-"
    else:
        raise ValueError(f"loại lệnh không hỗ trợ: {typ}")
    return [typ, target, action["id"], *extra]


class Responder:
    def __init__(self, es, api: WazuhAPI):
        self.es = es
        self.api = api
        self.platforms: dict[str, str] = {}      # agent_id -> os.platform, cập nhật mỗi lần đồng bộ

    def _platform(self, agent_id: str) -> str | None:
        if agent_id not in self.platforms:
            try:
                self.platforms[agent_id] = self.es.get(index=settings.IDX_AGENTS, id=agent_id)["_source"].get("platform")
            except Exception:  # noqa: BLE001 - chưa đồng bộ lần nào
                return None
        return self.platforms[agent_id]

    def dispatch(self) -> int:
        """Gửi mọi action pending xuống agent qua Wazuh. Trả về số lệnh đã gửi."""
        sent = 0
        for a in store.claim_pending_actions(self.es):
            try:
                res = self.api.active_response(a["agent_id"], ar_arguments(a), ar_script(self._platform(a["agent_id"])))
            except (ValueError, WazuhError) as e:
                store.finish_action(self.es, a["id"], a["agent_id"], "failed", str(e))
                log.warning("lệnh %s (%s) trên agent %s lỗi: %s", a["id"], a["type"], a["agent_id"], e)
                continue
            failed = res.get("data", {}).get("failed_items") or []
            if failed:
                msg = "; ".join(str((f.get("error") or {}).get("message", f)) for f in failed)
                store.finish_action(self.es, a["id"], a["agent_id"], "failed", f"Wazuh từ chối: {msg}")
                log.warning("Wazuh từ chối lệnh %s trên agent %s: %s", a["id"], a["agent_id"], msg)
                continue
            self.es.update(index=settings.IDX_ACTIONS, id=a["id"],
                           doc={"output": "đã gửi qua Wazuh active response, chờ agent báo kết quả",
                                "updated_at": store.now_iso()})
            log.info("đã gửi lệnh %s %s tới agent %s", a["type"], a.get("params"), a["agent_id"])
            sent += 1
        return sent

    def collect_results(self) -> int:
        """Khớp dòng kết quả script siem-xdr gửi về (event.action=response_result) với lệnh đang `sent`."""
        waiting = store.search(self.es, settings.IDX_ACTIONS, {"term": {"status": "sent"}}, size=200,
                               sort=[{"created_at": "asc"}])
        if not waiting:
            return 0
        by_id = {a["id"]: a for a in waiting}
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        events = store.search(self.es, f"{settings.IDX_EVENTS}-*", {"bool": {"filter": [
            {"term": {"event.action": "response_result"}}, {"terms": {"siem.action.id": list(by_id)}},
            {"range": {"@timestamp": {"gte": since}}}]}}, size=200)
        done = 0
        for ev in events:
            res = ev.get("siem", {}).get("action", {})
            a = by_id.get(res.get("id"))
            agent_id = (ev.get("agent") or {}).get("id")
            # agent chỉ báo được kết quả cho lệnh của CHÍNH nó (id lệnh ngẫu nhiên, không đoán được lệnh máy khác)
            if not a:
                continue
            try:
                ok = store.finish_action(self.es, a["id"], agent_id, res.get("status", "failed"), res.get("output", ""))
            except Exception as e:  # noqa: BLE001 - lỗi 1 lệnh không được chặn các lệnh khác
                log.warning("cập nhật kết quả lệnh %s lỗi: %s", a["id"], e)
                continue
            if ok:
                log.info("lệnh %s trên agent %s: %s %s", a["id"], agent_id, res.get("status"), res.get("output", ""))
                by_id.pop(a["id"])
                done += 1
        return done

    def sync_agents(self) -> int:
        """Danh sách agent lấy từ Wazuh (nguồn sự thật) -> siem-agents để console / SOAR (scope: all) dùng.
        Agent không còn trong Wazuh (đã xóa, hoặc bản ghi của agent cũ) bị xóa khỏi siem-agents."""
        agents = [ag for ag in self.api.agents() if ag.get("id") != "000"]     # 000 = chính wazuh-manager
        for ag in agents:
            osinfo = ag.get("os") or {}
            self.platforms[ag["id"]] = osinfo.get("platform")
            store.upsert_agent(self.es, {
                "agent_id": ag.get("id"), "hostname": ag.get("name"),
                "os": " ".join(x for x in (osinfo.get("name"), osinfo.get("version")) if x) or osinfo.get("platform"),
                "platform": osinfo.get("platform"), "version": ag.get("version"), "wazuh_status": ag.get("status"),
                "groups": ag.get("group"), "last_seen": ag.get("lastKeepAlive"),
            }, ag.get("ip"))
        self.es.delete_by_query(index=settings.IDX_AGENTS, conflicts="proceed", query={"bool": {"must_not": [
            {"terms": {"agent_id": [ag["id"] for ag in agents]}}]}})
        return len(agents)
