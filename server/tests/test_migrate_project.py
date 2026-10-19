"""tools/migrate_project.py: đổi tên project Compose siem-xdr -> soc-platform mà giữ dữ liệu (Docker giả lập)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[2] / "tools" / "migrate_project.py"
spec = importlib.util.spec_from_file_location("migrate_project", TOOL)
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)


class FakeDocker:
    """Giữ volume / container / network / image như Docker thật, ghi lại các lệnh làm thay đổi trạng thái."""

    def __init__(self, volumes=(), containers=(), networks=(), images=()):
        self.volumes = {name: {"project": name.split("_", 1)[0], "key": name.split("_", 1)[1]} for name in volumes}
        self.containers = [list(c) for c in containers]
        self.networks = list(networks)
        self.images = set(images)
        self.copy_output, self.calls = "3\n3\n", []        # số mục ở /from và /to sau khi cp -a

    def __call__(self, *args):
        a = list(args)
        if a[0] == "version":
            return "27.3.1\n"
        if a[:2] == ["volume", "ls"]:
            proj = a[3].split("=")[-1]
            return "".join(f"{n}\t{v['key']}\n" for n, v in self.volumes.items() if v["project"] == proj)
        if a[:2] == ["ps", "-a"]:
            proj = a[3].split("=")[-1]
            return "".join(f"{c[0]}\t{c[1]}\t{c[2]}\n" for c in self.containers if c[1].startswith(proj + "-"))
        if a[:2] == ["network", "ls"]:
            proj = a[3].split("=")[-1]
            return "".join(f"{i}\t{n}\n" for i, n, p in self.networks if p == proj)
        if a[:2] == ["image", "ls"]:
            return "".join(f"{i}\n" for i in sorted(self.images))
        self.calls.append(a)
        if a[0] == "rm":
            self.containers = [c for c in self.containers if c[0] not in a[1:]]
        elif a[:2] == ["network", "rm"]:
            self.networks = [n for n in self.networks if n[0] != a[2]]
        elif a[:2] == ["volume", "create"]:
            self.volumes[a[-1]] = {"project": a[3].split("=")[1], "key": a[5].split("=")[1]}
        elif a[0] == "run":
            return self.copy_output
        elif a[0] == "tag":
            self.images.add(a[2])
        return ""


OLD_VOLS = ["siem-xdr_esdata", "siem-xdr_wazuh_etc", "siem-xdr_certs"]


def make(tmp_path, env="", **kw):
    envf = tmp_path / ".env"
    envf.write_text(env, encoding="utf-8")
    fake = FakeDocker(**kw)
    return fake, mp.Migrator(run=fake, env_file=envf, out=lambda *_: None), envf


def test_plan_only_reads(tmp_path):
    fake, m, _ = make(tmp_path, volumes=OLD_VOLS, images=["siem-xdr-server:latest", "siem-xdr-demo-web:latest"],
                      containers=[("c1", "siem-xdr-elasticsearch-1", "running")])
    p = m.plan()
    assert set(p["old"]) == {"esdata", "wazuh_etc", "certs"} and p["new"] == {}
    assert p["old_images"] == ["siem-xdr-demo-web:latest"]        # siem-xdr-server là image đang dùng: không gợi ý xóa
    assert fake.calls == []                                   # không thay đổi gì khi chưa --apply


def test_apply_copies_every_volume_and_keeps_old(tmp_path):
    fake, m, envf = make(tmp_path, env="COMPOSE_PROJECT_NAME=siem-xdr\nKAFKA=x\n", volumes=OLD_VOLS,
                         images=["siem-xdr-server:latest", "siem-xdr-demo-web:latest"],
                         containers=[("c1", "siem-xdr-elasticsearch-1", "running"), ("c2", "siem-xdr-kafka-1", "exited")],
                         networks=[("n1", "soc-lab", "siem-xdr"), ("n2", "siem-xdr_grafana-auth", "siem-xdr")])
    old = m.apply(m.plan())
    assert old == sorted(OLD_VOLS)
    assert ["stop", "-t", "60", "c1", "c2"] in fake.calls and ["rm", "c1", "c2"] in fake.calls
    assert fake.networks == []                                # soc-lab có tên cố định: phải gỡ để Compose tạo lại
    for key in ("esdata", "wazuh_etc", "certs"):
        assert fake.volumes[f"soc-platform_{key}"] == {"project": "soc-platform", "key": key}
        assert fake.volumes[f"siem-xdr_{key}"]["project"] == "siem-xdr"          # volume cũ còn nguyên
    run = next(c for c in fake.calls if c[0] == "run")
    assert "siem-xdr_certs:/from:ro" in run and "soc-platform_certs:/to" in run and "--network" in run
    assert run[-3] == "siem-xdr-server:latest"                # image cũ chỉ dùng để chạy lệnh chép
    assert not any(c[0] == "tag" for c in fake.calls)         # không gắn tag: compose tự build image mới từ mã hiện tại
    assert envf.read_text(encoding="utf-8") == "COMPOSE_PROJECT_NAME=soc-platform\nKAFKA=x\n"
    assert not any(c[0] == "volume" and c[1] == "rm" for c in fake.calls)


def test_apply_refuses_when_new_volumes_exist(tmp_path):
    fake, m, _ = make(tmp_path, volumes=OLD_VOLS + ["soc-platform_esdata"], images=["siem-xdr-server:latest"],
                      containers=[("c1", "siem-xdr-elasticsearch-1", "running")])
    with pytest.raises(mp.MigrateError, match="soc-platform_esdata"):
        m.apply(m.plan())
    assert fake.calls == []                                   # chưa dừng gì


def test_apply_refuses_on_count_mismatch(tmp_path):
    fake, m, _ = make(tmp_path, volumes=OLD_VOLS[:1], images=["siem-xdr-server:latest"])
    fake.copy_output = "5\n4\n"
    with pytest.raises(mp.MigrateError, match="không khớp"):
        m.apply(m.plan())


def test_keep_name_and_env_editing(tmp_path):
    fake, m, envf = make(tmp_path, env="# COMPOSE_PROJECT_NAME=\nA=1", volumes=OLD_VOLS)
    m.keep_name(m.plan())
    assert envf.read_text(encoding="utf-8") == "COMPOSE_PROJECT_NAME=siem-xdr\nA=1"
    mp.set_env(envf, "B", "2")
    assert mp.get_env(envf, "B") == "2" and envf.read_text(encoding="utf-8").endswith("A=1\nB=2\n")


def test_compose_project_is_renamed():
    compose = (TOOL.parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert "\nname: soc-platform\n" in compose and f"image: {mp.APP_IMAGE}\n" in compose
