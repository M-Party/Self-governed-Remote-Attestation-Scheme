#!/usr/bin/env python3
"""
对指定网卡注入 netem delay，执行测试命令，结束后自动清理。

示例：
python3 performance/run_with_netem_delay.py --delay-ms 20 -- \
  python3 performance/performance_test.py --test phase2 --single 2
"""
import argparse
import os
import shlex
import signal
import subprocess
import sys


def _run(cmd):
    return subprocess.run(cmd, check=True)


def _clear_qdisc(dev):
    subprocess.run(
        ["sudo", "tc", "qdisc", "del", "dev", dev, "root"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _apply_delay(dev, delay_ms):
    if delay_ms <= 0:
        return
    one_way_ms = delay_ms / 2.0
    _run(["sudo", "tc", "qdisc", "replace", "dev", dev, "root", "netem", "delay", f"{one_way_ms}ms"])


def main():
    parser = argparse.ArgumentParser(description="Run a command with temporary tc netem delay")
    parser.add_argument("--delay-ms", type=float, required=True, help="target RTT delay in ms")
    parser.add_argument("--dev", type=str, default="lo", help="network device, default lo")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to run after --")
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing command after --")

    child = None

    def _cleanup_and_exit(signum=None, frame=None):
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
        _clear_qdisc(args.dev)
        if signum is not None:
            raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _cleanup_and_exit)
    signal.signal(signal.SIGTERM, _cleanup_and_exit)

    try:
        _clear_qdisc(args.dev)
        _apply_delay(args.dev, args.delay_ms)
        print("Applied netem RTT delay %.3f ms on %s" % (args.delay_ms, args.dev))
        child = subprocess.Popen(command)
        return_code = child.wait()
        return return_code
    finally:
        _clear_qdisc(args.dev)
        print("Cleared netem delay on %s" % args.dev)


if __name__ == "__main__":
    raise SystemExit(main())
