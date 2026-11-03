"""IOC MISP -> danh sách CDB của Wazuh (siem/pipeline/misp_cdb.py) + hook đẩy sau mỗi lần tải của MispFeed."""
from datetime import datetime, timezone

import pytest

from siem.pipeline import misp, misp_cdb
from siem.wazuh_rules import WazuhApi, WazuhRuleError

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def attr(value, type_="ip-dst", **kw):
    return {"to_ids": True, "type": type_, "value": value, "timestamp": str(int(NOW.timestamp())), "event_id": "7", **kw}


def test_hosts_and_small_cidrs_become_sorted_unique_lines():
    text = misp_cdb.to_cdb([attr("185.220.101.9"), attr("185.220.101.9", "ip-src"), attr("45.9.9.4/30"), attr(" 45.9.9.5|443 ", "ip-dst|port")],
                           now=NOW)
    assert text.splitlines() == [f"45.9.9.{i}:misp" for i in (4, 5, 6, 7)] + ["185.220.101.9:misp"]   # CIDR triển khai: Wazuh không khớp khóa CIDR


def test_slash24_expands_to_256_lines():
    assert len(misp_cdb.to_cdb([attr("45.9.9.0/24")], now=NOW).splitlines()) == 256


def test_total_lines_are_capped(monkeypatch):
    monkeypatch.setattr(misp_cdb, "MAX_ENTRIES", 300)
    assert len(misp_cdb.to_cdb([attr("45.9.9.0/24"), attr("45.9.10.0/24")], now=NOW).splitlines()) == 300


@pytest.mark.parametrize("bad", [
    "1.2.3.4\n5.6.7.8", "1.2.3.4:evil", "999.1.1.1", "evil.example.com", "", "::1", "2001:db8::1",
    "10.0.0.1", "192.168.1.0/24", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1",    # không phải địa chỉ public
    "0.0.0.0/0", "8.0.0.0/8", "8.8.0.0/16", "8.8.8.0/23",                                  # prefix < 24: quá rộng
    "8.8.8.8/24",                                                                        # bit máy: không tự nới thành /24
])
def test_malformed_or_dangerous_ioc_never_makes_a_line(bad):
    assert misp_cdb.to_cdb([attr(bad)], now=NOW) == misp_cdb.PLACEHOLDER + "\n"


def test_every_line_is_key_colon_label():
    text = misp_cdb.to_cdb([attr(v) for v in ("45.9.9.0/24", "45.9.9.1", "evil\n9.9.9.9:x")], now=NOW)
    for line in text.splitlines():
        key, sep, label = line.partition(":")
        assert sep and label == "misp" and "\n" not in key and ":" not in key


def test_non_ip_expired_and_non_ids_are_skipped():
    old = str(int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()))
    text = misp_cdb.to_cdb([attr("45.9.9.1", timestamp=old), attr("45.9.9.2", to_ids=False), attr("evil.example.com", "domain"),
                            attr("d41d8cd98f00b204e9800998ecf8427e", "md5"), attr("45.9.9.3")], now=NOW)
    assert text == "45.9.9.3:misp\n"


def test_empty_gives_placeholder_not_empty_file():
    assert misp_cdb.to_cdb([], now=NOW) == "240.0.0.0:empty\n"      # API Wazuh từ chối file rỗng


class FakeApi:
    def __init__(self, fail=None):
        self.puts, self.reloads, self.fail = [], 0, fail

    def put_list(self, name, text):
        if self.fail == "put":
            raise WazuhRuleError("boom")
        self.puts.append((name, text))

    def reload(self):
        self.reloads += 1
        if self.fail == "reload":
            raise WazuhRuleError("boom")


def items(*values):
    return misp.parse([attr(v) for v in values], now=NOW)


def test_sync_pushes_then_reloads_only_when_content_changes():
    api = FakeApi()
    sync = misp_cdb.MispListSync(api)
    assert sync.push(items("45.9.9.1")) is True
    assert sync.push(items("45.9.9.1")) is False               # cùng nội dung: không đẩy, không reload
    assert sync.push(items("45.9.9.1", "45.9.9.2")) is True
    assert [n for n, _ in api.puts] == ["siem-misp-ip"] * 2 and api.reloads == 2


@pytest.mark.parametrize("fail", ["put", "reload"])
def test_sync_retries_next_cycle_after_failure(fail):
    api = FakeApi(fail)
    sync = misp_cdb.MispListSync(api)
    with pytest.raises(WazuhRuleError):
        sync.push(items("45.9.9.1"))
    api.fail = None
    assert sync.push(items("45.9.9.1")) is True


def test_feed_refresh_calls_hook_and_survives_hook_error():
    body = b'{"response": {"Attribute": [%s]}}'
    import json

    class Resp:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return self.data

    seen = []
    feed = misp.MispFeed("https://misp", "k", opener=lambda req: Resp(body % json.dumps(attr("45.9.9.1")).encode()),
                         on_refresh=seen.append)
    assert feed.refresh() == 1 and seen and seen[0][0]["value"] == "45.9.9.1"
    feed.on_refresh = lambda items: 1 / 0
    assert feed.refresh() == 1 and feed.snapshot() is not None      # hook lỗi không làm mất IOC vừa tải


def test_put_list_raises_on_api_rejection(monkeypatch):
    api = WazuhApi("https://x:55000", "siem-rules", "pw")
    monkeypatch.setattr(api, "token", lambda: "t")
    bad = {"data": {"failed_items": [{"error": {"message": "Bad format in CDB list"}}]}, "error": 1}
    monkeypatch.setattr(api, "_open", lambda req: bad)
    with pytest.raises(WazuhRuleError, match="Bad format"):
        api.put_list("siem-misp-ip", "x\n")
    sent = []
    monkeypatch.setattr(api, "_open", lambda req: sent.append(req) or {"data": {"failed_items": []}, "error": 0})
    api.put_list("siem-misp-ip", "45.9.9.1:misp\n")
    assert sent[0].get_method() == "PUT" and sent[0].full_url.endswith("/lists/files/siem-misp-ip?overwrite=true")
    assert sent[0].data == b"45.9.9.1:misp\n"
