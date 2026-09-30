"""Test Manager API với ES/Kafka giả lập."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from siem import settings, store


@pytest.fixture()
def client(monkeypatch):
    actions = {}

    class ES:
        pass
    monkeypatch.setattr(store, "connect", lambda: ES())
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: actions.setdefault(
        "x1", {"id": "x1", "agent_id": aid, "type": t, "params": p, "status": "pending"}))
    from siem.manager import api
    with TestClient(api.app) as c:
        c.actions = actions
        yield c


def test_agent_endpoints_removed_and_actions_need_api_key(client):
    # agent là Wazuh agent: manager không còn nhận enroll / event / poll lệnh
    for path in ("/api/v1/agents/enroll", "/api/v1/events", "/api/v1/actions/x1/result"):
        assert client.post(path, json={}).status_code in (404, 405)
    body = {"agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4"}}
    assert client.post("/api/v1/actions", json=body).status_code == 401
    r = client.post("/api/v1/actions", json=body, headers={"X-API-Key": settings.API_KEY})
    assert r.status_code == 200 and client.actions["x1"]["status"] == "pending"     # SOAR gửi xuống qua Wazuh API


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
