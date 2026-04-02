#!/usr/bin/env python3
"""
批量启动多个 RPO
"""
import os
import sys
import time
import subprocess
import signal
import logging
import configparser

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class RPOStarter:
    def __init__(self, base_dir=None, num_parties=3):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        self.processes = []
    
    def update_policies_path(self):
        """根据参与方数量更新所有 RPO 的 config.toml 中的 policies_path"""
        policies_filename = f"policies-{self.num_parties}.json"
        logger.info("Updating policies_path to '%s' for all RPOs..." % policies_filename)
        
        for i in range(1, self.num_parties + 1):
            rpo_dir = os.path.join(self.base_dir, f"RPO_party{i}")
            if not os.path.exists(rpo_dir):
                logger.warning("RPO Party %d not found: %s" % (i, rpo_dir))
                continue
            
            config_file = os.path.join(rpo_dir, "config.toml")
            if not os.path.exists(config_file):
                logger.warning("Config file not found: %s" % config_file)
                continue
            
            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                if 'rpo' in config:
                    config['rpo']['policies_path'] = f'"{policies_filename}"'
                    with open(config_file, 'w') as f:
                        config.write(f)
                    logger.info("Updated RPO Party %d: policies_path = %s" % (i, policies_filename))
            except Exception as e:
                logger.error("Failed to update config for RPO Party %d: %s" % (i, str(e)))

    def start_all(self):
        """启动所有 RPO（并行启动）"""
        self.update_policies_path()
        logger.info("Starting RPOs...")
        rpo_configs = []
        for i in range(1, self.num_parties + 1):
            rpo_dir = os.path.join(self.base_dir, f"RPO_party{i}")
            if not os.path.exists(rpo_dir):
                logger.warning("RPO Party %d not found: %s" % (i, rpo_dir))
                continue
            startup_script = os.path.join(rpo_dir, "startup.sh")
            if not os.path.exists(startup_script):
                logger.warning("Startup script not found: %s" % startup_script)
                continue
            log_dir = os.path.join(rpo_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            rpo_configs.append((i, rpo_dir, log_dir, startup_script))
        for i, rpo_dir, log_dir, startup_script in rpo_configs:
            try:
                log_file = open(os.path.join(log_dir, f"rpo_party{i}.log"), "w")
                process = subprocess.Popen(
                    ["bash", startup_script, "start"],
                    cwd=rpo_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
                self.processes.append((f"rpo_party{i}", process, log_file))
                logger.info("RPO Party %d started (PID: %d)" % (i, process.pid))
            except Exception as e:
                logger.error("Failed to start RPO Party %d: %s" % (i, str(e)))
        if self.processes:
            logger.info("Waiting for all RPOs to bind...")
            time.sleep(3)
        logger.info("=" * 60)
        logger.info("All RPOs started!")
        logger.info("Total processes: %d" % len(self.processes))
        logger.info("=" * 60)
    
    def stop_all(self):
        """停止所有进程（含子进程，释放端口）"""
        import os
        logger.info("Stopping all RPOs...")
        for name, process, log_file in reversed(self.processes):
            try:
                logger.info("Stopping %s (PID: %d)..." % (name, process.pid))
                if process.poll() is None:
                    try:
                        pgid = os.getpgid(process.pid)
                        os.killpg(pgid, signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        pass
                time.sleep(1)
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

    def stop_by_port(self):
        """通过各 party 的 RPO 端口查找并终止进程"""
        logger.info("Stopping RPOs by ports...")
        for i in range(1, self.num_parties + 1):
            rpo_dir = os.path.join(self.base_dir, f"RPO_party{i}")
            config_file = os.path.join(rpo_dir, "config.toml")
            if not os.path.exists(config_file):
                logger.warning("Config file not found for RPO Party %d: %s" % (i, config_file))
                continue

            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                if "rpo" not in config or "port" not in config["rpo"]:
                    logger.warning("Port not found in config for RPO Party %d" % i)
                    continue
                port = int(config["rpo"]["port"].strip("'\""))
            except Exception as e:
                logger.error("Failed to read port for RPO Party %d: %s" % (i, str(e)))
                continue

            try:
                out = subprocess.run(
                    ["lsof", "-ti", ":%d" % port],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except FileNotFoundError:
                logger.warning("lsof not found; cannot stop RPO by port automatically")
                return
            except Exception as e:
                logger.error("Failed to inspect port %d for RPO Party %d: %s" % (port, i, str(e)))
                continue

            if out.returncode == 0 and out.stdout.strip():
                for pid_str in out.stdout.strip().split():
                    pid = int(pid_str)
                    logger.info("Killing PID %d (listening on port %d, rpo_party%d)" % (pid, port, i))
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            else:
                logger.info("No process found on port %d for rpo_party%d" % (port, i))

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="批量启动多个 RPO")
    parser.add_argument("--num-parties", type=int, required=True, help="参与方数量")
    parser.add_argument("--wait", type=int, default=0, help="等待时间（秒），0 表示持续运行")
    parser.add_argument("--stop", action="store_true", help="仅按端口清理已启动的 RPO 进程")
    
    args = parser.parse_args()
    
    starter = RPOStarter(num_parties=args.num_parties)
    if args.stop:
        starter.stop_by_port()
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
            logger.info("RPOs are running. Press Ctrl+C to stop.")
            while True:
                time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        starter.stop_all()

if __name__ == "__main__":
    main()
