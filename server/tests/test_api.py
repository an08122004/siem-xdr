"""Test Manager API với ES/Kafka giả lập."""
from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

from siem import bus, settings, store


class FakeProducer:
    def __init__(self):
        self.sent = []

    def produce(self, topic, value, key=None):
        self.sent.append((topic, json.loads(value), key))

    def poll(self, _t=0):
        return 0

    def flush(self, _t=0):
        return 0


@pytest.fixture()
def client(monkeypatch):
    agents, actions = {}, {}

    class ES:
        pass
    monkeypatch.setattr(store, "connect", lambda: ES())

    def upsert_agent(es, info, ip, extra=None):
        agents.setdefault(info["agent_id"], {}).update(info | {"ip": ip} | (extra or {}))
    monkeypatch.setattr(store, "upsert_agent", upsert_agent)
    monkeypatch.setattr(store, "get_agent", lambda es, aid: copy.deepcopy(agents.get(aid)))  # như ES: trả bản sao
    monkeypatch.setattr(store, "update_agent", lambda es, aid, fields: agents[aid].update(fields))
    monkeypatch.setattr(store, "claim_pending_actions",
                        lambda es, aid: [a for a in actions.values() if a["agent_id"] == aid and a["status"] == "pending"])
    monkeypatch.setattr(store, "finish_action", lambda es, i, aid, st, out: i in actions and actions[i]["agent_id"] == aid)
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: actions.setdefault(
        "x1", {"id": "x1", "agent_id": aid, "type": t, "params": p, "status": "pending"}))
    monkeypatch.setattr(bus, "wait_for_kafka", lambda: None)
    prod = FakeProducer()
    monkeypatch.setattr(bus, "producer", lambda: prod)
    from siem.manager import api
    api._cred_cache.clear()
    with TestClient(api.app) as c:
        c.prod, c.agents = prod, agents
        yield c


def test_enroll_ingest_and_actions(client):
    info = {"agent_id": "web-1", "hostname": "h", "os": "linux", "version": "1"}
    assert client.post("/api/v1/agents/enroll", json=info, headers={"X-Enrollment-Key": "sai"}).status_code == 403
    r = client.post("/api/v1/agents/enroll", json=info, headers={"X-Enrollment-Key": settings.ENROLLMENT_KEY})
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}", "X-Agent-ID": "web-1"}
    # token ngẫu nhiên, server chỉ giữ hash
    from siem.manager import api
    assert token != api.legacy_token("web-1") and token not in json.dumps(client.agents)

    # token của agent này không dùng được cho agent khác (chống giả mạo)
    assert client.post("/api/v1/events", json=[], headers={**h, "X-Agent-ID": "other"}).status_code == 401

    evs = [{"source": "file", "event_type": "apache_access", "agent_id": "spoofed", "data": {"message": "x"}}] * 3
    r = client.post("/api/v1/events", json=evs, headers=h)
    assert r.json() == {"accepted": 3}
    topic, value, key = [m for m in client.prod.sent if m[1].get("event_type") != "agent_audit"][0]
    assert topic == settings.TOPIC_RAW and value["agent_id"] == "web-1" and key == b"web-1"

    # analyst tạo lệnh -> agent poll được -> báo kết quả
    assert client.post("/api/v1/actions", json={"agent_id": "web-1", "type": "block_ip", "params": {"ip": "1.2.3.4"}}).status_code == 401
    r = client.post("/api/v1/actions", json={"agent_id": "web-1", "type": "block_ip", "params": {"ip": "1.2.3.4"}},
                    headers={"X-API-Key": settings.API_KEY})
    assert r.status_code == 200
    polled = client.get("/api/v1/agents/actions", headers=h).json()
    assert polled[0]["type"] == "block_ip"
    assert client.post("/api/v1/actions/x1/result", json={"status": "success", "output": "ok"}, headers=h).status_code == 200


def test_console_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "SIEM/XDR Console" in r.text


def test_case_workflow(client):
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

    fake = CaseES()
    api._state["es"] = fake
    h = {"X-API-Key": settings.API_KEY}
    r = client.patch("/api/v1/cases/c1", json={"analyst": "an", "task_index": 0, "task_done": True}, headers=h)
    assert r.status_code == 200 and fake.doc["tasks"][0]["done_by"] == "an"
    # đóng case bắt buộc có kết luận
    assert client.patch("/api/v1/cases/c1", json={"analyst": "an", "status": "closed"}, headers=h).status_code == 400
    r = client.patch("/api/v1/cases/c1", json={"analyst": "an", "status": "closed", "note": "đã xử lý"}, headers=h)
    assert r.status_code == 200 and fake.doc["status"] == "closed" and fake.doc["closed_at"]
    assert [n["by"] for n in fake.doc["notes"]] == ["an", "an", "an"]
    assert client.patch("/api/v1/cases/c1", json={"analyst": "an", "status": "bậy"}, headers=h).status_code == 422
    assert client.patch("/api/v1/cases/c1", json={"analyst": "an"}).status_code == 401


# ---------------------------------------------------------------------------
# Enroll: khóa enroll dùng chung không đủ để nhận danh tính agent đã có
# ---------------------------------------------------------------------------

KEY = {"X-Enrollment-Key": settings.ENROLLMENT_KEY}
INFO = {"agent_id": "web-1", "hostname": "h", "os": "linux", "version": "1"}
ANALYST = {"X-API-Key": settings.API_KEY}


def _enroll(client, token=None, info=INFO):
    h = dict(KEY)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return client.post("/api/v1/agents/enroll", json=info, headers=h)


def _hb(client, token, agent_id="web-1"):
    return client.post("/api/v1/agents/heartbeat", json={**INFO, "agent_id": agent_id},
                       headers={"Authorization": f"Bearer {token}", "X-Agent-ID": agent_id})


def _audits(client, action):
    return [v["data"] for t, v, k in client.prod.sent if v.get("event_type") == "agent_audit" and v["data"]["action"] == action]


def test_enroll_existing_agent_is_rejected(client):
    token = _enroll(client).json()["token"]
    assert _hb(client, token).status_code == 200            # agent thật đã dùng token

    # kẻ có khóa enroll chung xin token cho agent_id đang có -> bị từ chối và bị ghi audit
    r = _enroll(client)
    assert r.status_code == 409
    assert _audits(client, "agent_enroll_conflict")
    assert _enroll(client, token="token-doan-bua").status_code == 409
    assert _hb(client, token).status_code == 200            # agent thật không bị ảnh hưởng


def test_enroll_retry_when_response_lost(client):
    first = _enroll(client).json()["token"]                 # phản hồi coi như mất, agent chưa dùng token
    second = _enroll(client).json()["token"]                # cùng IP, chưa xác nhận -> cho thử lại
    assert first != second
    assert _hb(client, first).status_code == 401
    assert _hb(client, second).status_code == 200
    assert _enroll(client).status_code == 409               # đã xác nhận -> hết cửa thử lại


def test_enroll_rotation_with_current_token(client):
    old = _enroll(client).json()["token"]
    _hb(client, old)
    new = _enroll(client, token=old).json()["token"]
    assert _hb(client, old).status_code == 401
    assert _hb(client, new).status_code == 200


def test_legacy_hmac_agent_migrates(client):
    from siem.manager import api
    client.agents["web-1"] = dict(INFO)                     # agent của bản cũ: có trong ES, chưa có token_hash
    legacy = api.legacy_token("web-1")
    assert _hb(client, legacy).status_code == 401            # token HMAC không còn gọi API được
    assert _enroll(client).status_code == 409               # không trình token cũ -> không được
    new = _enroll(client, token=legacy)
    assert new.status_code == 200 and client.agents["web-1"]["enroll_reason"] == "legacy"
    assert _hb(client, new.json()["token"]).status_code == 200


def test_revoke_and_allow_reenroll(client):
    token = _enroll(client).json()["token"]
    _hb(client, token)
    who = {"analyst": "an", "reason": "máy nghi bị chiếm"}
    assert client.post("/api/v1/agents/web-1/revoke", json=who).status_code == 401   # cần API key
    assert client.post("/api/v1/agents/web-1/revoke", json=who, headers=ANALYST).status_code == 200
    assert _hb(client, token).status_code == 401
    assert _enroll(client, token=token).status_code == 409  # bị thu hồi thì không tự enroll lại được

    # cho enroll lại nhưng chỉ từ IP khác -> máy này vẫn không được
    r = client.post("/api/v1/agents/web-1/allow-reenroll", json={**who, "ip": "10.9.9.9"}, headers=ANALYST)
    assert r.status_code == 200 and _enroll(client).status_code == 409
    client.post("/api/v1/agents/web-1/allow-reenroll", json=who, headers=ANALYST)
    new = _enroll(client)
    assert new.status_code == 200 and _hb(client, new.json()["token"]).status_code == 200
    assert _enroll(client).status_code == 409               # quyền enroll lại chỉ dùng một lần
    assert client.post("/api/v1/agents/nope/revoke", json=who, headers=ANALYST).status_code == 404


def test_list_agents_hides_token_hash():
    class ES:
        def search(self, **_kw):
            return {"hits": {"hits": [{"_source": {"agent_id": "a", "last_seen": store.now_iso(),
                                                   "token_hash": "x", "prev_token_hash": "y"}}]}}
    [a] = store.list_agents(ES())
    assert "token_hash" not in a and "prev_token_hash" not in a
    assert a["enrollment"] == "ok" and a["status"] == "online"
