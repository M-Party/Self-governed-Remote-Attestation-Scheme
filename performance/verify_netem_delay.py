#!/usr/bin/env python3
"""
用本地 TCP echo RTT 验证 netem delay 是否生效。

示例：
python3 performance/verify_netem_delay.py --host 127.0.0.1 --port 39001 --count 10
"""
import argparse
import socket
import statistics
import threading
import time


def _echo_server(host, port, ready):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    srv.close()


def main():
    parser = argparse.ArgumentParser(description="Verify effective RTT under tc netem delay")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=39001)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=16)
    args = parser.parse_args()

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_echo_server,
        args=(args.host, args.port, ready),
        daemon=True,
    )
    server_thread.start()
    ready.wait(timeout=5)

    payload = b"x" * args.payload_bytes
    samples_ms = []
    with socket.create_connection((args.host, args.port), timeout=5) as conn:
        for _ in range(args.count):
            start = time.perf_counter()
            conn.sendall(payload)
            remaining = len(payload)
            while remaining > 0:
                data = conn.recv(remaining)
                if not data:
                    raise RuntimeError("connection closed early")
                remaining -= len(data)
            end = time.perf_counter()
            samples_ms.append((end - start) * 1000.0)

    avg_ms = statistics.mean(samples_ms)
    med_ms = statistics.median(samples_ms)
    print("RTT samples (ms):", ", ".join("%.3f" % x for x in samples_ms))
    print("RTT avg (ms): %.3f" % avg_ms)
    print("RTT median (ms): %.3f" % med_ms)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
