#!/usr/bin/env python3
"""
Start or stop multiple P2P Quote exchange service instances.
"""
import argparse
import configparser
import logging
import os
import signal
import subprocess
import sys
import time


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class P2PQuoteExchangeStarter:
    def __init__(self, base_dir=None, num_parties=3, base_port=51051, host="127.0.0.1"):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        self.base_port = base_port
        self.host = host
        self.processes = []

    def _node_address(self, party_id):
        return "%s:%d" % (self.host, self.base_port + party_id - 1)

    def start(self):
        log_dir = os.path.join(self.base_dir, "performance_data", "logs")
        os.makedirs(log_dir, exist_ok=True)
        script_path = os.path.join(self.base_dir, "performance", "p2p_quote_exchange.py")
        for party_id in range(1, self.num_parties + 1):
            port = self.base_port + party_id - 1
            peer_addresses = [
                self._node_address(peer_id)
                for peer_id in range(1, self.num_parties + 1)
                if peer_id != party_id
            ]
            log_path = os.path.join(log_dir, "p2p_quote_exchange_party%d.log" % party_id)
            log_file = open(log_path, "w")
            process = subprocess.Popen(
                [
                    "python3",
                    script_path,
                    "--port",
                    str(port),
                    "--node-id",
                    "party%d" % party_id,
                    "--peer-addresses",
                    ",".join(peer_addresses),
                ],
                cwd=self.base_dir,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.processes.append((party_id, process, log_file))
            logger.info(
                "P2P node party%d started on %s (PID: %d, peers=%s)",
                party_id,
                self._node_address(party_id),
                process.pid,
                peer_addresses,
            )
        time.sleep(2)

    def stop(self):
        for party_id, process, log_file in reversed(self.processes):
            try:
                if process.poll() is None:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        pass
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            finally:
                log_file.close()
        self.processes = []

    def stop_by_port(self):
        for party_id in range(1, self.num_parties + 1):
            port = self.base_port + party_id - 1
            try:
                out = subprocess.run(
                    ["lsof", "-ti", ":%d" % port],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip():
                    for pid_str in out.stdout.strip().split():
                        pid = int(pid_str)
                        logger.info("Killing PID %d on port %d", pid, port)
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
            except FileNotFoundError:
                logger.warning("lsof not found; cannot stop by port automatically")
                break


def main():
    parser = argparse.ArgumentParser(description="Start multi-node P2P Quote exchange")
    parser.add_argument("--num-parties", type=int, default=3, help="number of p2p nodes")
    parser.add_argument("--base-port", type=int, default=51051, help="base gRPC port for p2p nodes")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="peer host address")
    parser.add_argument("--wait", type=int, default=0, help="Wait N seconds before exit")
    parser.add_argument("--stop", action="store_true", help="Stop the service by port")
    args = parser.parse_args()

    starter = P2PQuoteExchangeStarter(
        num_parties=args.num_parties,
        base_port=args.base_port,
        host=args.host,
    )
    if args.stop:
        starter.stop_by_port()
        return

    def signal_handler(sig, frame):
        logger.info("Received signal %s, stopping P2P service...", sig)
        starter.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        starter.start()
        if args.wait > 0:
            time.sleep(args.wait)
            starter.stop()
        else:
            while True:
                time.sleep(10)
    finally:
        starter.stop()


if __name__ == "__main__":
    main()
