#!/usr/bin/env python3
"""
批量启动多个 Fabric Client
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
        """启动所有 Fabric Client"""
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
                time.sleep(3)  # 等待启动
            except Exception as e:
                logger.error("Failed to start Fabric Client Party %d: %s" % (i, str(e)))
        
        logger.info("=" * 60)
        logger.info("All Fabric Clients started!")
        logger.info("Total processes: %d" % len(self.processes))
        logger.info("=" * 60)
    
    def stop_all(self):
        """停止所有进程"""
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

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="批量启动多个 Fabric Client")
    parser.add_argument("--num-parties", type=int, required=True, help="参与方数量")
    parser.add_argument("--wait", type=int, default=0, help="等待时间（秒），0 表示持续运行")
    
    args = parser.parse_args()
    
    starter = FabricClientStarter(num_parties=args.num_parties)
    
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