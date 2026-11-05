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
    # lần đầu đẩy cả ba danh sách (domain / hash là dòng giữ chỗ) rồi nạp lại MỘT lần; lần đổi sau chỉ đẩy danh sách IP
    assert [n for n, _ in api.puts] == ["siem-misp-ip", "siem-misp-domain", "siem-misp-hash", "siem-misp-ip"] and api.reloads == 2


def dh(domains=(), hashes=()):
    return misp.parse([attr(d, "domain") for d in domains] + [attr(h, "sha256") for h in hashes], now=NOW)


def test_sync_pushes_domain_and_hash_lists_and_only_changed_ones():
    api = FakeApi()
    sync = misp_cdb.MispListSync(api)
    sha = "a" * 64
    assert sync.push(dh(["evil.example"], [sha])) is True
    assert dict(api.puts) == {"siem-misp-ip": "240.0.0.0:empty\n", "siem-misp-domain": "evil.example:misp\n", "siem-misp-hash": sha + ":misp\n"}
    api.puts.clear()
    assert sync.push(dh(["evil.example"], [sha])) is False and not api.puts
    assert sync.push(dh(["evil.example", "b.test"], [sha])) is True
    assert [n for n, _ in api.puts] == ["siem-misp-domain"] and api.reloads == 2


def test_sync_failure_on_second_list_retries_whole_changed_group():
    api = FakeApi()
    sync = misp_cdb.MispListSync(api)
    real = api.put_list
    api.put_list = lambda n, t: (_ for _ in ()).throw(WazuhRuleError("boom")) if n == "siem-misp-hash" else real(n, t)
    with pytest.raises(WazuhRuleError):
        sync.push(dh(["evil.example"]))
    api.put_list = real
    api.puts.clear()
    assert sync.push(dh(["evil.example"])) is True and {n for n, _ in api.puts} == set(misp_cdb.LISTS.values())


def cdb(values, kind, type_):
    return misp_cdb.to_cdb([attr(v, type_) for v in values], now=NOW, kind=kind)


def test_domains_are_validated_lowercased_idna_and_deduplicated():
    text = cdb(["Evil-C2.Example", "evil-c2.example.", "bücher.example", "a.b.c.example", "xn--bcher-kva.example"], "domain", "domain")
    assert text.splitlines() == ["a.b.c.example:misp", "evil-c2.example:misp", "xn--bcher-kva.example:misp"]


@pytest.mark.parametrize("bad", [
    "", "example", "*.evil.example", "evil.example:80", "evil .example", "evil.example\nx.example", "-evil.example", "evil-.example",
    "ev_il.example", "a..example", ".example", "1.2.3.4", "evil.123", "a" * 64 + ".example", ("a." * 130) + "example", "http://evil.example/x",
])
def test_bad_domains_never_make_a_line(bad):
    assert cdb([bad], "domain", "domain") == misp_cdb.PLACEHOLDERS["domain"] + "\n"


def test_hashes_accept_only_md5_sha1_sha256_hex_lowercased():
    good = {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    text = cdb([good["md5"].upper(), good["sha1"], good["sha256"], good["md5"]], "hash", "md5")
    assert text.splitlines() == sorted(f"{v}:misp" for v in good.values())


@pytest.mark.parametrize("bad", ["", "xyz", "d41d8cd98f00b204e9800998ecf8427", "d41d8cd98f00b204e9800998ecf8427ee", "g" * 32, "a" * 63,
                                 "d41d8cd98f00b204e9800998ecf8427e\n" + "a" * 32, "d41d8cd98f00b204e9800998ecf8427e:x"])
def test_bad_hashes_never_make_a_line(bad):
    assert cdb([bad], "hash", "md5") == misp_cdb.PLACEHOLDERS["hash"] + "\n"


def test_domain_and_hash_lists_are_capped_and_kinds_do_not_leak(monkeypatch):
    monkeypatch.setattr(misp_cdb, "MAX_ENTRIES", 3)
    assert len(cdb([f"d{i}.example" for i in range(10)], "domain", "domain").splitlines()) == 3
    assert len(cdb([f"{i:032x}" for i in range(10)], "hash", "md5").splitlines()) == 3
    mixed = misp.parse([attr("45.9.9.1"), attr("evil.example", "domain"), attr("a" * 32, "md5")], now=NOW)
    assert misp_cdb.render(mixed, "ip") == "45.9.9.1:misp\n" and misp_cdb.render(mixed, "domain") == "evil.example:misp\n" \
        and misp_cdb.render(mixed, "hash") == "a" * 32 + ":misp\n"


def test_every_domain_and_hash_line_is_key_colon_label():
    for kind, vals, t in (("domain", ["a.example", "b.example\nc.example", "d:e.example"], "domain"), ("hash", ["a" * 32, "b" * 40 + "\n", "c" * 64], "md5")):
        for line in cdb(vals, kind, t).splitlines():
            key, sep, label = line.partition(":")
            assert sep and label in ("misp", "empty") and ":" not in key and key.strip() == key


def test_local_domain_and_hash_files_are_exported(tmp_path):
    from siem.pipeline.enrich import ThreatIntel
    (tmp_path / "bad_domains.txt").write_text("# c\nevil-c2.example  # C2\nMalware-Download.test\n", encoding="utf-8")
    (tmp_path / "bad_hashes.txt").write_text("44d88612fea8a8f36de82e1278abb02f\n", encoding="utf-8")
    ind = ThreatIntel(tmp_path).indicators()
    assert misp_cdb.render(ind, "domain").splitlines() == ["evil-c2.example:misp", "malware-download.test:misp"]
    assert misp_cdb.render(ind, "hash") == "44d88612fea8a8f36de82e1278abb02f:misp\n"


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


def test_local_intel_and_feed_are_merged_and_documentation_ranges_kept(tmp_path):
    from siem.pipeline.enrich import IOCSet, ThreatIntel
    lines = ["# c", "203.0.113.66  # C2 mẫu", "10.0.0.9", "8.8.8.8/24", "không-phải-ip"]
    (tmp_path / "bad_ips.txt").write_text("\n".join(lines), encoding="utf-8")
    feed = type("F", (), {"snapshot": lambda self: IOCSet(items(" 45.9.9.1"))})()
    text = misp_cdb.render(ThreatIntel(tmp_path, feed=feed).indicators())
    assert text.splitlines() == ["45.9.9.1:misp", "203.0.113.66:misp"]     # IP riêng 10.0.0.9, bit máy 8.8.8.8/24, rác: bị loại
