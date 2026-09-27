"""Test Manager API với ES/Kafka giả lập."""
from __future__ import annotations

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
    monkeypatch.setattr(store, "upsert_agent", lambda es, info, ip: agents.__setitem__(info["agent_id"], info | {"ip": ip}))
    monkeypatch.setattr(store, "claim_pending_actions",
                        lambda es, aid: [a for a in actions.values() if a["agent_id"] == aid and a["status"] == "pending"])
    monkeypatch.setattr(store, "finish_action", lambda es, i, aid, st, out: i in actions and actions[i]["agent_id"] == aid)
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: actions.setdefault(
        "x1", {"id": "x1", "agent_id": aid, "type": t, "params": p, "status": "pending"}))
    monkeypatch.setattr(bus, "wait_for_kafka", lambda: None)
    prod = FakeProducer()
    monkeypatch.setattr(bus, "producer", lambda: prod)
    from siem.manager import api
    with TestClient(api.app) as c:
        c.prod, c.agents = prod, agents
        yield c


def test_enroll_ingest_and_actions(client):
    info = {"agent_id": "web-1", "hostname": "h", "os": "linux", "version": "1"}
    assert client.post("/api/v1/agents/enroll", json=info, headers={"X-Enrollment-Key": "sai"}).status_code == 403
    r = client.post("/api/v1/agents/enroll", json=info, headers={"X-Enrollment-Key": settings.ENROLLMENT_KEY})
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}", "X-Agent-ID": "web-1"}

    # token của agent này không dùng được cho agent khác (chống giả mạo)
    assert client.post("/api/v1/events", json=[], headers={**h, "X-Agent-ID": "other"}).status_code == 401

    evs = [{"source": "file", "event_type": "apache_access", "agent_id": "spoofed", "data": {"message": "x"}}] * 3
    r = client.post("/api/v1/events", json=evs, headers=h)
    assert r.json() == {"accepted": 3}
    topic, value, key = client.prod.sent[0]
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
