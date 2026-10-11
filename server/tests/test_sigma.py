"""Test rule Sigma do AI viết: đọc câu trả lời của model, biên dịch sang rule engine, tách / ghép vế, xuất YAML."""
from __future__ import annotations

import pytest

from siem.ai import sigma
from siem.ai.sigma import SigmaError
from siem.ai.validate import missing_fields, weak_values
from siem.detection.rules import Rule


def proc(cmd: str, image: str, parent: str = "C:\\Windows\\explorer.exe") -> dict:
    name = image.replace("/", "\\").rsplit("\\", 1)[-1]
    return {"event": {"category": "process"},
            "process": {"executable": image, "name": name, "command_line": cmd,
                        "parent": {"executable": parent, "name": parent.rsplit("\\", 1)[-1]}}}


def matcher(rule_text: str, domain: str = "windows"):
    cond, _ = sigma.compile_rule(sigma.parse(rule_text), domain)
    return Rule.from_dict({"id": "x", "title": "x", "condition": cond}).condition.match


NTDS = r"""Rule cho kỹ thuật T1003.003:
```yaml
title: NTDS dump
logsource:
  category: process_creation
  product: windows
detection:
  selection_ntds:
    Image|endswith: '\ntdsutil.exe'
    CommandLine|contains|all:
      - 'ac i ntds'
      - 'ifm'
  selection_vss:
    - Image|endswith: '\vssadmin.exe'
      CommandLine|contains: 'create shadow'
    - CommandLine|contains: 'shadowcopy call create'
  filter:
    ParentImage|endswith: '\backup.exe'
  condition: 1 of selection_* and not filter
level: high
```
Rule này bắt ntdsutil và vssadmin."""


def test_parse_takes_the_yaml_block_and_compiles_to_engine_conditions():
    m = matcher(NTDS)
    assert m(proc('ntdsutil "ac i ntds" ifm "create full C:\\x" q q', "C:\\Windows\\System32\\ntdsutil.exe"))
    assert m(proc("vssadmin.exe create shadow /for=C:", "C:\\Windows\\System32\\VSSADMIN.EXE"))   # không phân biệt hoa
    assert m(proc("wmic shadowcopy call create Volume=C:\\", "C:\\Windows\\System32\\wbem\\WMIC.exe"))
    assert not m(proc("ntdsutil snapshot", "C:\\Windows\\System32\\ntdsutil.exe"))         # thiếu 'ifm' (|all)
    assert not m(proc("vssadmin list shadows", "C:\\Windows\\System32\\vssadmin.exe"))
    assert not m(proc("vssadmin.exe create shadow /for=C:", "C:\\Windows\\System32\\vssadmin.exe",
                      parent="C:\\Program Files\\Veeam\\backup.exe"))                  # filter loại trừ


def test_image_endswith_maps_to_program_name_for_logs_without_full_path():
    m = matcher("detection:\n  sel:\n    Image|endswith: '/cat'\n    CommandLine|contains: '/etc/shadow'\n"
                "  condition: sel\n", "linux")
    linux = {"process": {"executable": "cat", "name": "cat", "command_line": "cat /etc/shadow"}}   # Splunk auditd
    assert m(linux) and m({"process": {"executable": "/usr/bin/cat", "name": "cat", "command_line": "cat /etc/shadow"}})


def test_modifiers_wildcards_and_windash():
    m = matcher(r"""detection:
  sel_enc:
    CommandLine|windash|contains: ' -enc '
  sel_glob:
    CommandLine: '*rundll32*,#2*'
  sel_re:
    CommandLine|re: 'certutil(\.exe)?\s+-urlcache'
  condition: 1 of sel_*
""")
    assert m(proc("powershell /enc SQBFAFgA", "p.exe")) and m(proc("powershell -enc SQBFAFgA", "p.exe"))
    assert m(proc("rundll32.exe x.dll,#2", "r.exe")) and not m(proc("rundll32.exe x.dll,Open", "r.exe"))
    assert m(proc("CERTUTIL.exe -urlcache -f http://x", "c.exe"))           # regex cũng không phân biệt hoa thường
    assert sigma._glob("C:\\\\Win*", None) == ("startswith", "C:\\Win")    # '\\' trước ký tự thường = 1 dấu '\'
    assert sigma._glob(r"a\*b", None) == ("eq", "a*b")                     # '\*' = dấu * thật


def test_web_query_matches_raw_and_decoded_forms():
    m = matcher("detection:\n  sel:\n    cs-uri-query|contains: \"' or 'a'='a\"\n  condition: sel\n", "web")
    raw = {"url": {"path": "/login", "query": "u=%27+or+%27a%27%3D%27a",
                   "decoded": "/login?u=' or 'a'='a"}}
    assert m(raw)
    m2 = matcher("detection:\n  sel:\n    cs-uri-query|contains: '%2527'\n  condition: sel\n", "web")
    assert m2({"url": {"path": "/x", "query": "id=%2527", "decoded": "/x?id=%27"}})        # mã hóa hai lần: chuỗi thô


def test_unavailable_fields_are_dropped_from_or_and_reported_in_and():
    cond, notes = sigma.compile_rule(sigma.parse(
        "detection:\n  img:\n    - Image|endswith: '\\reg.exe'\n    - OriginalFileName: reg.exe\n  condition: img\n"),
        "windows")
    assert cond == {"field": "process.name", "op": "eq", "value": "reg.exe"} and "OriginalFileName" in notes[0]
    with pytest.raises(SigmaError, match="never match.*OriginalFileName"):
        sigma.compile_rule(sigma.parse("detection:\n  sel:\n    OriginalFileName: reg.exe\n    CommandLine|contains: "
                                       "save\n  condition: sel\n"), "windows")


@pytest.mark.parametrize("text, msg", [
    ("detection:\n  sel: lsass\n  condition: sel\n", "must map field names"),
    ("detection:\n  sel:\n    Image: x\n  condition: sel | count() > 3\n", "aggregations"),
    ("detection:\n  filter:\n    Image: x\n  condition: sel and filter\n", "'sel', which is not a selection"),
    ("detection:\n  sel:\n    CommandLine|base64offset|contains: x\n  condition: sel\n", "modifier 'base64offset'"),
    ("detection:\n  sel:\n    Image: x\n  condition: 2 of sel\n", "'2 of' is not supported"),
    ("detection:\n  sel:\n    Image: x\n  condition: not sel\n", "matches every event|outside 'not'"),
    ("title: chỉ có tiêu đề\n", "detection"),
    ("detection: [\n", "invalid YAML"),
])
def test_unusable_rules_explain_why_in_english_for_the_model(text, msg):
    with pytest.raises(SigmaError, match=msg):
        rule = sigma.parse(text)
        sigma.compile_rule(rule, "windows")
        sigma.atoms(rule)


def test_parse_repairs_windows_paths_in_double_quotes_and_reads_no_rule():
    rule = sigma.parse('detection:\n  sel:\n    Image|endswith: "\\Windows\\reg.exe"\n  condition: sel\n')
    assert rule["detection"]["sel"]["Image|endswith"] == "\\Windows\\reg.exe"
    assert sigma.parse("```yaml\nno_rule: hoạt động sao lưu thường ngày\n```") == {"no_rule": "hoạt động sao lưu thường ngày"}


def test_atoms_split_and_assemble_keep_the_same_meaning():
    rule = sigma.parse(NTDS)
    atoms = sigma.atoms(rule)
    assert [sigma.atom_condition(a) for a in atoms] == ["selection_ntds and not filter", "selection_vss and not filter"]
    parts = sigma.split(atoms[1])                       # selection là danh sách 2 map -> 2 vế
    assert len(parts) == 2 and sigma.split(parts[1]) == []
    det = sigma.assemble([atoms[0], *parts])            # 2 vế con cùng cha ghép lại thành danh sách như cũ
    assert det["condition"] == "(selection_ntds_1 and not filter_1) or (selection_vss_2 and not filter_2)"
    assert det["selection_vss_2"] == rule["detection"]["selection_vss"]
    a, b = matcher(NTDS), matcher(sigma.dump({"detection": det}))
    docs = [proc("vssadmin create shadow", "C:\\vssadmin.exe"), proc("ntdsutil ac i ntds ifm", "C:\\ntdsutil.exe"),
            proc("wmic shadowcopy call create", "C:\\wmic.exe"), proc("vssadmin list", "C:\\vssadmin.exe"),
            proc("vssadmin create shadow", "C:\\vssadmin.exe", parent="C:\\backup.exe")]
    assert [a(d) for d in docs] == [b(d) for d in docs] == [True, True, True, False, False]
    only = sigma.assemble([parts[1]])                   # chỉ giữ 1 phần
    assert only == {"selection_vss": {"CommandLine|contains": "shadowcopy call create"},
                    "filter": {"ParentImage|endswith": "\\backup.exe"}, "condition": "selection_vss and not filter"}


def test_value_lists_are_split_one_value_per_atom():
    rule = sigma.parse("detection:\n  sel:\n    Image|endswith: '\\reg.exe'\n    CommandLine|contains:\n"
                       "      - ' save '\n      - ' export '\n      - ' query '\n  condition: sel\n")
    parts = sigma.split(sigma.atoms(rule)[0])
    assert [p["detection"]["sel"]["CommandLine|contains"] for p in parts] == [" save ", " export ", " query "]
    det = sigma.assemble(parts[:2])                     # bỏ ' query ' (khớp lệnh bình thường)
    assert det["sel"]["CommandLine|contains"] == [" save ", " export "] and det["condition"] == "sel"


def test_render_produces_a_standard_sigma_rule_that_parses_back():
    rule = sigma.parse(NTDS)
    text = sigma.render(rule, title="NTDS dump", description="Phát hiện dump NTDS.\nDòng 2.", level="medium",
                        techniques=["T1003.003"], tactic="credential-access", logsource=sigma.LOGSOURCE["windows"],
                        author="siem-xdr AI worker")
    back = sigma.parse(text)
    assert back["tags"] == ["attack.credential-access", "attack.t1003.003"] and back["level"] == "medium"
    assert back["detection"] == rule["detection"] and back["logsource"] == {"category": "process_creation",
                                                                            "product": "windows"}
    assert "Image|endswith: '\\ntdsutil.exe'" in text and "&id" not in text
    assert sigma.attack_tags(["attack.T1003.003", "attack.t1003", "attack.credential-access", "attack.sqli-x",
                              "attack.g0016"]) == (["T1003.003", "T1003"], "credential-access")


def _cond(text: str, domain: str = "windows"):
    return sigma.compile_rule(sigma.parse(text), domain)[0]


def test_short_words_are_fine_when_tied_to_a_specific_program():
    tied = _cond("detection:\n  sel:\n    Image|endswith: '\\ntdsutil.exe'\n    CommandLine|contains: 'ifm'\n"
                 "  condition: sel\n")
    alone = _cond("detection:\n  sel:\n    CommandLine|contains: 'ifm'\n  condition: sel\n")
    shell = _cond("detection:\n  sel:\n    Image|endswith: '\\cmd.exe'\n    CommandLine|contains: 'stop'\n"
                  "  condition: sel\n")
    suffix = _cond("detection:\n  sel:\n    Image|endswith: '.exe'\n    CommandLine|contains: 'stop'\n"
                   "  condition: sel\n")
    both = _cond("detection:\n  sel:\n    CommandLine|contains|all: ['startup', 'autostart']\n  condition: sel\n")
    strong = _cond("detection:\n  sel:\n    CommandLine|contains|all: ['save', 'hklm\\sam']\n  condition: sel\n")
    filt = _cond("detection:\n  sel:\n    CommandLine|contains: 'hklm\\sam'\n  f:\n    CommandLine|contains: '/c'\n"
                 "  condition: sel and not f\n")
    assert weak_values(tied) == [] and weak_values(alone) == ["ifm"]
    assert weak_values(shell) == ["stop"] and weak_values(suffix) == ["stop"]      # cmd.exe / đuôi .exe không phải neo
    assert weak_values(both) == [] and weak_values(strong) == [] and weak_values(filt) == []


def test_missing_fields_counts_an_or_branch_only_when_every_option_is_missing():
    cond = _cond("detection:\n  sel:\n    cs-uri-stem|endswith: '.bak'\n  condition: sel\n", "web")
    assert missing_fields(cond, [{"url": {"path": "/a.bak"}}]) == []                 # không có url.decoded vẫn được
    assert missing_fields(cond, [{"http": {}}]) == ["url.decoded", "url.path"]


def test_empty_and_star_values_and_keyword_searches():
    m = matcher("detection:\n  sel:\n    ParentImage|endswith: '\\rundll32.exe'\n    CommandLine: ''\n"
                "  condition: sel\n")
    assert m(proc("", "C:\\dllhost.exe", parent="C:\\Windows\\rundll32.exe"))
    assert not m(proc("dllhost.exe /Processid:{x}", "C:\\dllhost.exe", parent="C:\\Windows\\rundll32.exe"))
    star = sigma.compile_rule(sigma.parse("detection:\n  sel:\n    User: '*'\n  condition: sel\n"), "windows")[0]
    assert star == {"field": "user.name", "op": "exists", "value": True}
    web = matcher("detection:\n  m:\n    cs-method: POST\n  kw:\n    - u0027\n    - '%u0027'\n"
                  "  condition: m and kw\n", "web")
    assert web({"http": {"request": {"method": "POST"}}, "url": {"original": "/a?x=\\u0027", "decoded": "/a?x=\\u0027"}})
    assert not web({"http": {"request": {"method": "GET"}}, "url": {"original": "/a?x=u0027"}})
    rule = sigma.parse("detection:\n  kw:\n    - 'whoami /all'\n    - 'net user'\n  condition: kw\n")
    parts = sigma.split(sigma.atoms(rule)[0])
    assert [p["detection"]["kw"] for p in parts] == [["whoami /all"], ["net user"]]
    assert sigma.assemble(parts) == rule["detection"]


def test_relax_reads_all_lists_as_or_and_drops_filters():
    """Chạy thật 8/10 (SQLi): model đặt danh sách lựa chọn dưới |contains|all và thêm filter loại cả tấn công."""
    rule = sigma.parse("detection:\n  sel:\n    cs-uri-query|contains|all:\n      - \"'or'\"\n      - \"'a'='a\"\n"
                       "      - ' and 1=1'\n  filter:\n    sc-status: 200\n  condition: sel and not filter\n")
    atom = sigma.atoms(rule)[0]
    no_filter, as_or = sigma.relax(atom)
    assert no_filter["neg"] == [] and as_or["neg"] == ["filter"]
    assert as_or["detection"]["sel"] == {"cs-uri-query|contains": ["'or'", "'a'='a", " and 1=1"]}
    attack = {"url": {"query": "u=%27or%27a%27%3D%27a", "decoded": "/login?u='or'a'='a"},
              "http": {"response": {"status_code": 200}}}
    match = lambda a: Rule.from_dict({"id": "x", "title": "x", "condition": sigma.compile_rule(
        sigma.atom_rule(a), "web")[0]}).condition.match(attack)
    assert not match(atom) and not match(as_or) and not match(no_filter)   # mỗi lần nới chỉ đổi một thứ
    both = sigma.relax(no_filter)[0]                             # vòng ghép vế nới tiếp phần con
    assert match(both) and both["neg"] == [] and sigma.relax(both) == []   # hết chỗ nới


def test_generalize_offers_broader_atoms_and_relax_splits_all_of():
    """Chạy thật 8/10 (T1087.002): AdFind gắn với đúng đối số train + filter loại powershell -> 0% bài thử chưa thấy."""
    rule = sigma.parse("detection:\n  sel:\n    Image|endswith: '\\AdFind.exe'\n    CommandLine|contains: '-sc admincountdmp'\n"
                       "  filter:\n    Image|endswith: '\\powershell.exe'\n  condition: sel and not filter\n")
    gens = sigma.generalize(sigma.atoms(rule)[0])
    dets = [g["detection"] for g in gens]
    assert {"sel": rule["detection"]["sel"]} in dets                                   # bỏ filter
    assert {"sel": {"Image|endswith": "\\AdFind.exe"}, "filter": rule["detection"]["filter"]} in dets   # bỏ đối số
    allof = sigma.parse("detection:\n  selection_a:\n    CommandLine|contains: 'net user /domain'\n"
                        "  selection_b:\n    CommandLine|contains: 'kerbrute'\n  condition: all of selection_*\n")
    parts = sigma.relax(sigma.atoms(allof)[0])                  # model viết all of thay cho 1 of
    assert [p["pos"] for p in parts] == [["selection_a"], ["selection_b"]]


def test_unreadable_condition_falls_back_to_any_selection_minus_filters():
    """Chạy thật 8/10 (T1548.002): model viết biểu thức trên trường ngay trong condition -> YAML hỏng."""
    text = ("```yaml\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - 'reg.exe add'\n"
            "      - 'mscfile\\shell\\open\\command'\n  filter_btool:\n    CommandLine|contains: btool\n"
            "  condition: selection and not (CommandLine|contains|all: 'btool') and not 'reg.exe add'\n```")
    rule = sigma.parse(text)
    assert rule["detection"]["condition"] == "(selection) and not (filter_btool)" and "_condition_fixed" in rule
    m = matcher(text)
    assert m(proc("reg.exe add hkcu\\software\\classes\\mscfile\\shell\\open\\command /ve /d x /f", "C:\\reg.exe"))
    assert not m(proc("reg.exe add hkcu\\software\\classes\\mscfile\\shell\\open\\command btool", "C:\\reg.exe"))
    wrong_name = sigma.parse("detection:\n  sel_a:\n    CommandLine|contains: 'net user /domain'\n"
                             "  condition: selection_a\n")
    assert wrong_name["detection"]["condition"] == "sel_a"


def test_unquoted_colons_and_repeated_keys_are_repaired():
    """Chạy thật 8/10 (T1036.003): description không nháy chứa 'ví dụ: svchost' -> YAML hỏng; CommandLine|contains
    lặp 3 lần trong một selection -> YAML giữ lần cuối, mất ý AND."""
    text = ("```yaml\ntitle: Masquerading\ndetection:\n  sel:\n    Image|endswith: \\cmd.exe\n"
            "    CommandLine|contains: 'copy'\n    CommandLine|contains: '/K'\n  condition: sel\n"
            "description: Phát hiện sao chép công cụ hệ thống (ví dụ: svchost.exe) rồi chạy lại.\n```")
    rule = sigma.parse(text)
    assert rule["description"].startswith("Phát hiện") and "ví dụ: svchost" in rule["description"]
    assert rule["detection"]["sel"] == {"Image|endswith": "\\cmd.exe", "CommandLine|contains|all": ["copy", "/K"]}
    m = matcher(text)
    assert m(proc("cmd.exe /K copy a b", "C:\\cmd.exe")) and not m(proc("cmd.exe /K dir", "C:\\cmd.exe"))


def test_file_extension_alone_is_not_a_signature_but_fine_with_a_program():
    """Chạy thật 8/10 (T1218.011 log thật): `CommandLine|contains: '.inf'` đứng riêng qua kiểm định với 100%."""
    alone = _cond("detection:\n  sel:\n    CommandLine|contains: '.inf'\n  condition: sel\n")
    tied = _cond("detection:\n  sel:\n    Image|endswith: '\\rundll32.exe'\n    CommandLine|contains: '.inf'\n"
                 "  condition: sel\n")
    assert weak_values(alone) == [".inf"] and weak_values(tied) == []
