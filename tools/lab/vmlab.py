"""Dựng lab máy ảo VMware Workstation cho SOC Platform: biến thể "SIEM chạy trên Docker của máy host" (DEPLOY-VM.md).

Không cần quyền admin trên máy host: 3 vùng là VMware LAN segment (khai báo trong .vmx), vùng SOC là VMnet1 host-only có sẵn.

  fw (OPNsense nano)  WAN    VMnet8 NAT, DHCP             ra Internet thật để cài gói
                      SOC    VMnet1 192.168.241.2/24      máy host 192.168.241.1 = SIEM (Docker: 1514/1515, 514, 8000)
                      DMZ    segment soclab-dmz   .254    Web-01 10.10.20.20
                      USERS  segment soclab-users .254    Ubuntu-01 10.10.30.21, PC-01 10.10.30.30
                      INET   segment soclab-inet  .1      attacker 203.0.113.50 / .51 (Internet giả)

Máy host không có route tới 10.10.x.x (thêm route cần admin), nên firewall NAT lưu lượng từ DMZ / USERS tới máy host ra địa
chỉ 192.168.241.2, và mở port forward trên cổng SOC để máy host SSH vào từng VM (2220 Web-01, 2221 Ubuntu-01, 2222 attacker).

Thư mục lab (image, VM, khóa SSH): biến SOCLAB_DIR, mặc định D:/GSANM/BTL/lab.
"""
from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

VMWARE = Path(os.getenv("VMWARE_DIR", r"C:\Program Files (x86)\VMware\VMware Workstation"))
LAB = Path(os.getenv("SOCLAB_DIR", "D:/GSANM/BTL/lab"))
VMS, IMAGES = LAB / "vms", LAB / "images"

# LAN segment: các VM cùng pvnID nằm chung một switch ảo không có máy host
SEGMENTS = {
    "dmz": "52 c0 1a 10 10 20 00 01-5c 0c 1a 10 10 20 00 01",
    "users": "52 c0 1a 10 10 30 00 01-5c 0c 1a 10 10 30 00 01",
    "inet": "52 c0 1a cb 00 71 00 01-5c 0c 1a cb 00 71 00 01",
}


class LabError(RuntimeError):
    pass


def run(exe: Path | str, *args: str, check: bool = True, timeout: float = 600) -> str:
    p = subprocess.run([str(exe), *map(str, args)], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout)
    if check and p.returncode != 0:
        raise LabError(f"{Path(str(exe)).name} {' '.join(map(str, args))[:200]}: {(p.stdout + p.stderr).strip()[:500]}")
    return p.stdout + p.stderr


def vmrun(*args: str, check: bool = True, timeout: float = 600) -> str:
    return run(VMWARE / "vmrun.exe", "-T", "ws", *args, check=check, timeout=timeout)


def vdisk(*args: str) -> str:
    return run(VMWARE / "vmware-vdiskmanager.exe", *args, timeout=3600)


def mkiso(out: Path, src: Path, label: str) -> Path:
    """ISO9660 + Joliet + Rock Ridge (cloud-init NoCloud cần nhãn 'cidata'; Windows Setup đọc autounattend.xml ở gốc)."""
    run(VMWARE / "mkisofs.exe", "-quiet", "-J", "-R", "-V", label, "-o", out, src)
    return out


def running() -> set[str]:
    return {Path(line.strip()).name.lower() for line in vmrun("list").splitlines()[1:] if line.strip()}


def write_vmx(path: Path, settings: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f'{k} = "{v}"\n' for k, v in settings.items())
    path.write_text('.encoding = "UTF-8"\n' + body, encoding="utf-8", newline="\n")
    return path


def base_vmx(name: str, guest: str, cpus: int, mem_mb: int, firmware: str = "bios") -> dict[str, str]:
    d = {"config.version": "8", "virtualHW.version": "20", "displayName": f"soclab-{name}", "guestOS": guest,
         "numvcpus": str(cpus), "memsize": str(mem_mb), "firmware": firmware, "uuid.action": "create",
         "msg.autoAnswer": "TRUE", "tools.syncTime": "TRUE", "mks.enable3d": "FALSE", "sound.present": "FALSE",
         "usb.present": "FALSE", "floppy0.present": "FALSE", "vmci0.present": "TRUE", "hpet0.present": "TRUE",
         "pciBridge0.present": "TRUE"}
    # cầu PCIe như VM do giao diện VMware tạo: không có thì card mạng thứ 5 trở đi báo "no more PCI slots"
    for b in (4, 5, 6, 7):
        d.update({f"pciBridge{b}.present": "TRUE", f"pciBridge{b}.virtualDev": "pcieRootPort",
                  f"pciBridge{b}.functions": "8"})
    return d


def nic(i: int, net: str, mac: str, dev: str = "e1000") -> dict[str, str]:
    """net: 'nat' (VMnet8), 'hostonly' (VMnet1) hoặc tên segment trong SEGMENTS."""
    d = {f"ethernet{i}.present": "TRUE", f"ethernet{i}.virtualDev": dev, f"ethernet{i}.addressType": "static",
         f"ethernet{i}.address": mac, f"ethernet{i}.startConnected": "TRUE"}
    if net in ("nat", "hostonly"):
        d[f"ethernet{i}.connectionType"] = net
    else:
        d[f"ethernet{i}.connectionType"] = "pvn"
        d[f"ethernet{i}.pvnID"] = SEGMENTS[net]
    return d


def raw_to_vmdk(raw: Path, out: Path, grow_to: str | None = None) -> Path:
    """Đĩa raw (vd image nano của OPNsense) -> vmdk growable: descriptor 'monolithicFlat' trỏ vào file raw, rồi chuyển."""
    sectors = raw.stat().st_size // 512
    desc = raw.with_suffix(".flat-desc.vmdk")
    desc.write_text(
        "# Disk DescriptorFile\nversion=1\nencoding=\"UTF-8\"\nCID=fffffffe\nparentCID=ffffffff\n"
        "createType=\"monolithicFlat\"\n\n"
        f"RW {sectors} FLAT \"{raw.name}\" 0\n\n"
        "ddb.adapterType = \"lsilogic\"\n"
        f"ddb.geometry.cylinders = \"{max(1, sectors // (255 * 63))}\"\nddb.geometry.heads = \"255\"\n"
        "ddb.geometry.sectors = \"63\"\nddb.virtualHWVersion = \"20\"\n", encoding="ascii", newline="\n")
    vdisk("-r", desc, "-t", "0", out)
    desc.unlink()
    if grow_to:
        vdisk("-x", grow_to, out)
    return out


# ------------------------------------------------------------------ console serial qua named pipe
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_k32.PeekNamedPipe.restype = wintypes.BOOL


class Serial:
    """Client của named pipe mà VMware tạo cho cổng serial của VM (serialN.fileType = pipe, VM là server).

    Chỉ một luồng: PeekNamedPipe xem có bao nhiêu byte rồi đọc đúng chừng đó, nên không bao giờ chặn khi đọc, và ghi
    không phải chờ một lệnh đọc đang treo trên cùng handle."""

    def __init__(self, pipe: str, wait: float = 120, log: Path | None = None):
        path = r"\\.\pipe" + "\\" + pipe
        deadline = time.time() + wait
        while True:
            try:
                self.f = open(path, "r+b", buffering=0)
                break
            except OSError:
                if time.time() > deadline:
                    raise LabError(f"không mở được {path} (VM đã bật chưa?)")
                time.sleep(1)
        self.h = msvcrt.get_osfhandle(self.f.fileno())
        self.buf = b""
        self.log = open(log, "ab") if log else None

    def poll(self) -> None:
        n = wintypes.DWORD()
        if not _k32.PeekNamedPipe(self.h, None, 0, None, ctypes.byref(n), None):
            raise LabError(f"PeekNamedPipe lỗi {ctypes.get_last_error()}")
        if n.value:
            data = self.f.read(n.value)
            self.buf += data
            if self.log:
                self.log.write(data)
                self.log.flush()

    def expect(self, pattern: str, timeout: float = 60) -> re.Match:
        rx = re.compile(pattern.encode(), re.S)
        deadline = time.time() + timeout
        while True:
            self.poll()
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            if time.time() > deadline:
                tail = self.buf[-600:].decode("utf-8", "replace")
                raise LabError(f"hết {timeout:.0f} giây chờ {pattern!r}; cuối màn hình:\n{tail}")
            time.sleep(0.05)

    def send(self, text: str, delay: float = 0.0) -> None:
        for ch in text.encode():
            self.f.write(bytes([ch]))
            if delay:
                time.sleep(delay)

    def sh(self, cmd: str, timeout: float = 120, check: bool = True) -> str:
        """Chạy lệnh trong /bin/sh của VM, trả về đầu ra. Đầu ra nằm giữa hai mốc in ra trên dòng riêng, nên dòng lệnh
        được echo lại (kể cả khi terminal tự xuống dòng) không lẫn vào."""
        n = int(time.time() * 1000) % 10**8
        start, end = f"__S{n}__", f"__E{n}__"
        self.buf = b""
        # mốc trên dòng riêng: lệnh có heredoc thì dòng kết thúc heredoc vẫn đứng một mình
        self.send(f"echo {start}\r{cmd}\recho {end}$?{end}\r", delay=0.001)
        m = self.expect(r"(?m)^" + re.escape(start) + r"\r?\n(.*?)" + re.escape(end) + r"(\d+)" + re.escape(end), timeout)
        out = m.group(1).decode("utf-8", "replace").replace("\r", "")
        if check and m.group(2) != b"0":
            raise LabError(f"lệnh lỗi ({m.group(2).decode()}): {cmd[:120]}\n{out[-800:]}")
        return out

    def close(self) -> None:
        self.f.close()
        if self.log:
            self.log.close()
