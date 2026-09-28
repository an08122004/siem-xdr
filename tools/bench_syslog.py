"""Đo khả năng chịu tải của syslog collector (log BÌNH THƯỜNG, không kích hoạt rule nào).

    python tools/bench_syslog.py --host 127.0.0.1 --port 5514 --count 100000 --rate 20000 [--tcp]

In ra tốc độ gửi thực tế. Số message thực sự vào Kafka đo riêng bằng offset của topic
(xem hướng dẫn trong README mục "Đánh giá syslog collector").
"""
import argparse
import socket
import sys
import time


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--count", type=int, default=100000)
    ap.add_argument("--rate", type=int, default=0, help="msg/giây, 0 = nhanh nhất có thể")
    ap.add_argument("--tcp", action="store_true")
    ap.add_argument("--tag", default="bench")
    a = ap.parse_args()

    if a.tcp:
        s = socket.create_connection((a.host, a.port))
        send = lambda b: s.sendall(b + b"\n")  # noqa: E731  (TCP: framing theo dòng)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send = lambda b: s.sendto(b, (a.host, a.port))  # noqa: E731
    batch = 500
    t0 = time.perf_counter()
    for i in range(a.count):
        send(f"<14>Sep 27 10:00:00 bench-host benchapp[{i % 30000}]: {a.tag} message seq={i} status=ok".encode())
        if a.rate and i % batch == batch - 1:
            ahead = (i + 1) / a.rate - (time.perf_counter() - t0)
            if ahead > 0:
                time.sleep(ahead)
    if a.tcp:
        # đóng chiều ghi rồi chờ collector đọc hết và đóng kết nối -> không mất dữ liệu còn trong buffer
        s.shutdown(socket.SHUT_WR)
        while s.recv(4096):
            pass
    dt = time.perf_counter() - t0
    s.close()
    print(f"đã gửi {a.count} msg trong {dt:.2f}s = {a.count / dt:,.0f} msg/s ({'TCP' if a.tcp else 'UDP'})")


if __name__ == "__main__":
    main()
