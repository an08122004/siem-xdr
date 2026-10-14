"""VM firewall F001 (OPNsense nano, console serial). Xem vmlab.py cho mô hình mạng.

    python tools/lab/fw.py create        # đĩa + .vmx từ image nano đã giải nén (lab/vms/fw/opnsense-nano.img)
    python tools/lab/fw.py start         # bật VM (không mở cửa sổ)
    python tools/lab/fw.py sh "lệnh"     # chạy lệnh shell qua console serial (đã đăng nhập root)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmlab  # noqa: E402

DIR = vmlab.VMS / "fw"
VMX = DIR / "fw.vmx"
PIPE = "soclab-fw"
# thứ tự card = em0..em4 trong OPNsense
NICS = [("nat", "WAN"), ("hostonly", "SOC"), ("dmz", "DMZ"), ("users", "USERS"), ("inet", "INET_GIA")]
MACS = [f"00:50:56:2A:00:1{i}" for i in range(len(NICS))]
ROOT_PASSWORD = "opnsense"          # mật khẩu mặc định của image nano; đổi bằng `passwd` sau khi dựng xong


def create() -> None:
    raw = DIR / "opnsense-nano.img"
    disk = DIR / "fw.vmdk"
    if not disk.exists():
        if not raw.exists():
            raise vmlab.LabError(f"thiếu {raw}: giải nén OPNsense-*-nano-amd64.img.bz2 vào đó trước")
        vmlab.raw_to_vmdk(raw, disk, grow_to="8GB")
        raw.unlink()                                         # bản .bz2 gốc vẫn còn trong lab/images
    s = vmlab.base_vmx("fw", "freebsd14-64", 2, 2048)
    s.update({"sata0.present": "TRUE", "sata0:0.present": "TRUE", "sata0:0.fileName": disk.name,
              "serial0.present": "TRUE", "serial0.fileType": "pipe", "serial0.fileName": "\\\\.\\pipe\\" + PIPE,
              "serial0.pipe.endPoint": "server", "serial0.tryNoRxLoss": "FALSE", "serial0.startConnected": "TRUE"})
    for i, ((net, _), mac) in enumerate(zip(NICS, MACS)):
        s.update(vmlab.nic(i, net, mac))
    vmlab.write_vmx(VMX, s)
    print("đã tạo", VMX)


def start() -> None:
    if VMX.name.lower() not in vmlab.running():
        vmlab.vmrun("start", VMX, "nogui")
    print("fw đang chạy")


def console(wait: float = 120) -> vmlab.Serial:
    return vmlab.Serial(PIPE, wait=wait, log=DIR / "console.log")


def login(c: vmlab.Serial, timeout: float = 600) -> None:
    """Đăng nhập root trên console, thoát menu của OPNsense sang /bin/sh."""
    c.send("\r")
    m = c.expect(r"(login: |Enter an option: |# )", timeout)
    if m.group(1) == b"login: ":
        c.send("root\r")
        c.expect(r"Password:", 30)
        c.send(ROOT_PASSWORD + "\r")
        m = c.expect(r"(Enter an option: |# )", 60)
    if m.group(1) == b"Enter an option: ":
        c.send("8\r")
        c.expect(r"# ", 30)
    c.send("exec /bin/sh\r")
    time.sleep(1)
    # sh của FreeBSD soạn dòng bằng libedit và tự echo, bất kể stty: tắt soạn dòng rồi mới tắt echo của tty
    c.send("set +o emacs +o vi 2>/dev/null; PS1='# '; stty -echo; export PAGER=cat\r")
    time.sleep(1)


def get_file(c: vmlab.Serial, remote: str, local: Path) -> Path:
    """Chép file từ VM về máy host qua console (base64), kiểm SHA-256."""
    import base64
    import hashlib
    data = base64.b64decode(c.sh(f"openssl base64 -in {remote}", timeout=300))
    want = c.sh(f"sha256 -q {remote}").strip()
    if hashlib.sha256(data).hexdigest() != want:
        raise vmlab.LabError(f"chép {remote} lỗi: SHA-256 không khớp")
    local.write_bytes(data)
    return local


def put_file(c: vmlab.Serial, local: Path, remote: str) -> None:
    """Chép file từ máy host vào VM qua console: base64 từng dòng ngắn (dòng tty có giới hạn), kiểm SHA-256."""
    import base64
    import hashlib
    data = local.read_bytes()
    b64 = base64.b64encode(data).decode()
    c.sh(f": > {remote}.b64")
    for i in range(0, len(b64), 3000):                    # mỗi lệnh ~3 KB, mỗi dòng 76 ký tự
        chunk = b64[i:i + 3000]
        lines = "\n".join(chunk[j:j + 76] for j in range(0, len(chunk), 76))
        c.sh(f"cat >> {remote}.b64 <<'EOF_B64'\n{lines}\nEOF_B64", timeout=120)
    c.sh(f"openssl base64 -d -in {remote}.b64 -out {remote} && rm -f {remote}.b64")
    got = c.sh(f"sha256 -q {remote}").strip()
    if got != hashlib.sha256(data).hexdigest():
        raise vmlab.LabError(f"chép vào {remote} lỗi: SHA-256 không khớp")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "create":
        create()
    elif cmd == "start":
        start()
    elif cmd == "sh":
        c = console()
        login(c)
        print(c.sh(" ".join(sys.argv[2:]), timeout=600))
        c.close()
    else:
        print(__doc__)
