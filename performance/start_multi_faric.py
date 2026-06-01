#!/usr/bin/env python3
"""
Start multiple Fabric Client instances.
"""
import os
import sys
import time
import subprocess
import signal
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class FabricClientStarter:
    def __init__(self, base_dir=None, num_parties=3):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        self.processes = []
    
    def start_all(self):
        """Start all Fabric Client instances."""
        logger.info("Starting Fabric Clients...")
        for i in range(1, self.num_parties + 1):
            fc_dir = os.path.join(self.base_dir, f"fabric_client_party{i}")
            if not os.path.exists(fc_dir):
                logger.warning("Fabric Client Party %d not found: %s" % (i, fc_dir))
                continue
            
            startup_script = os.path.join(fc_dir, "startup.sh")
            if not os.path.exists(startup_script):
                logger.warning("Startup script not found: %s" % startup_script)
                continue
            
            log_dir = os.path.join(fc_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            try:
                log_file = open(os.path.join(log_dir, f"fabric_client_party{i}.log"), "w")
                process = subprocess.Popen(
                    ["bash", startup_script, "start"],
                    cwd=fc_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT
                )
                self.processes.append((f"fabric_client_party{i}", process, log_file))
                logger.info("Fabric Client Party %d started (PID: %d)" % (i, process.pid))
                time.sleep(3)  # Wait for startup.
            except Exception as e:
                logger.error("Failed to start Fabric Client Party %d: %s" % (i, str(e)))
        
        logger.info("=" * 60)
        logger.info("All Fabric Clients started!")
        logger.info("Total processes: %d" % len(self.processes))
        logger.info("=" * 60)
    
    def stop_all(self):
        """Stop all processes."""
        logger.info("Stopping all Fabric Clients...")
        for name, process, log_file in reversed(self.processes):
            try:
                logger.info("Stopping %s (PID: %d)..." % (name, process.pid))
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                log_file.close()
            except Exception as e:
                logger.error("Error stopping %s: %s" % (name, str(e)))
        self.processes.clear()

    def stop_all_by_ports(self):
        """Find and terminate processes by each party's gRPC port."""
        import configparser
        logger.info("Stopping Fabric Clients by ports...")
        base_port = 50051
        for i in range(1, self.num_parties + 1):
            port = base_port + (i - 1)
            config_file = os.path.join(self.base_dir, f"fabric_client_party{i}", "config", "config.toml")
            if os.path.isfile(config_file):
                try:
                    config = configparser.ConfigParser()
                    config.read(config_file)
                    if "grpc" in config and "port" in config["grpc"]:
                        port_str = config["grpc"]["port"].strip("'\"")
                        port = int(port_str)
                except Exception:
                    pass
            try:
                out = subprocess.run(
                    ["lsof", "-ti", ":%d" % port],
                    capture_output=True, text=True, timeout=5
                )
                if out.returncode == 0 and out.stdout.strip():
                    for pid_str in out.stdout.strip().split():
                        pid = int(pid_str)
                        logger.info("Killing PID %d (listening on port %d, fabric_client_party%d)" % (pid, port, i))
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        except Exception as e:
                            logger.warning("Failed to kill PID %d: %s" % (pid, e))
            except FileNotFoundError:
                # Fall back to fuser when lsof is unavailable.
                try:
                    out = subprocess.run(
                        ["fuser", "-k", "%d/tcp" % port],
                        capture_output=True, text=True, timeout=5
                    )
                    if out.returncode == 0:
                        logger.info("Killed process on port %d (fabric_client_party%d)" % (port, i))
                except FileNotFoundError:
                    logger.warning("lsof/fuser not found, cannot kill by port. Run: lsof -ti :%d | xargs kill" % port)
            except Exception as e:
                logger.warning("Error stopping party %d (port %d): %s" % (i, port, e))
        logger.info("Done.")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Start multiple Fabric Client instances")
    parser.add_argument("--num-parties", type=int, required=True, help="Number of parties")
    parser.add_argument("--wait", type=int, default=0, help="Wait time in seconds; 0 means keep running")
    parser.add_argument("--stop", action="store_true", help="Only clean up started Fabric Client processes by port")
    
    args = parser.parse_args()
    
    starter = FabricClientStarter(num_parties=args.num_parties)
    
    if args.stop:
        starter.stop_all_by_ports()
        return
    
    def signal_handler(sig, frame):
        logger.info("Received interrupt signal, stopping all processes...")
        starter.stop_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        starter.start_all()
        
        if args.wait > 0:
            logger.info("Waiting %d seconds before exit..." % args.wait)
            time.sleep(args.wait)
            starter.stop_all()
        else:
            logger.info("Fabric Clients are running. Press Ctrl+C to stop.")
            while True:
                time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        starter.stop_all()

if __name__ == "__main__":
    main()
