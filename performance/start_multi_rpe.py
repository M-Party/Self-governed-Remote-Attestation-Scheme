#!/usr/bin/env python3
"""
批量启动多个 RPE
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

class RPEStarter:
    def __init__(self, base_dir=None, num_parties=3):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        self.processes = []
    
    def start_all(self):
        """启动所有 RPE（并行启动）"""
        logger.info("Starting RPEs...")
        
        # 先收集所有需要启动的 RPE 信息
        rpe_configs = []
        for i in range(1, self.num_parties + 1):
            rpe_dir = os.path.join(self.base_dir, f"RPE_party{i}")
            if not os.path.exists(rpe_dir):
                logger.warning("RPE Party %d not found: %s" % (i, rpe_dir))
                continue
            
            startup_script = os.path.join(rpe_dir, "startup.sh")
            if not os.path.exists(startup_script):
                logger.warning("Startup script not found: %s" % startup_script)
                continue
            
            log_dir = os.path.join(rpe_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            rpe_configs.append((i, rpe_dir, log_dir, startup_script))
            
        # 清理所有 RPE 的性能文件（启动前清理）
        import glob
        logger.info("Cleaning up performance data files...")
        for i, rpe_dir, log_dir, startup_script in rpe_configs:
            perf_data_dir = os.path.join(rpe_dir, "performance_data")
            if os.path.exists(perf_data_dir):
                for perf_file in glob.glob(os.path.join(perf_data_dir, "rpe_perf_*.json")):
                    try:
                        os.remove(perf_file)
                        logger.debug("Removed performance file: %s" % perf_file)
                    except Exception as e:
                        logger.warning("Failed to remove performance file %s: %s" % (perf_file, e))
        
        # 并行启动所有 RPE
        for i, rpe_dir, log_dir, startup_script in rpe_configs:
            try:
                rpe_id = f"rpe-{i}"
                log_file = open(os.path.join(log_dir, f"rpe_party{i}.log"), "w")
                process = subprocess.Popen(
                    ["bash", startup_script, "start"],
                    cwd=rpe_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
                self.processes.append((f"rpe_party{i}", process, log_file))
                logger.info("RPE Party %d (%s) started (PID: %d)" % (i, rpe_id, process.pid))
            except Exception as e:
                logger.error("Failed to start RPE Party %d: %s" % (i, str(e)))
        
        # 所有 RPE 启动后，等待一小段时间确保启动完成
        if self.processes:
            logger.info("Waiting for all RPEs to initialize...")
            time.sleep(3)  # 等待所有 RPE 完成启动初始化
        
        logger.info("=" * 60)
        logger.info("All RPEs started!")
        logger.info("Total processes: %d" % len(self.processes))
        logger.info("=" * 60)
    
    def stop_all(self):
        """停止所有进程（含子进程，释放端口），并删除各 RPE 目录下的 rpe_pre_init_ready_*.flag"""
        import os
        import glob

        # 先删除 flag，让 performance_test --manual 在 0.5s 内检测到「已清空」并重试，再慢慢停进程
        for i in range(1, self.num_parties + 1):
            perf_data_dir = os.path.join(self.base_dir, f"RPE_party{i}", "performance_data")
            if os.path.isdir(perf_data_dir):
                for flag_file in glob.glob(os.path.join(perf_data_dir, "rpe_pre_init_ready_*.flag")):
                    try:
                        os.remove(flag_file)
                        logger.info("Removed flag: %s" % flag_file)
                    except Exception as e:
                        logger.warning("Failed to remove flag %s: %s" % (flag_file, e))
        logger.info("Stopping all RPEs...")
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
        """通过各 party 的 RPE 端口查找并终止进程，并删除各 RPE 目录下的 rpe_pre_init_ready_*.flag"""
        import glob

        for i in range(1, self.num_parties + 1):
            perf_data_dir = os.path.join(self.base_dir, f"RPE_party{i}", "performance_data")
            if os.path.isdir(perf_data_dir):
                for flag_file in glob.glob(os.path.join(perf_data_dir, "rpe_pre_init_ready_*.flag")):
                    try:
                        os.remove(flag_file)
                        logger.info("Removed flag: %s" % flag_file)
                    except Exception as e:
                        logger.warning("Failed to remove flag %s: %s" % (flag_file, e))

        logger.info("Stopping RPEs by ports...")
        for i in range(1, self.num_parties + 1):
            rpe_dir = os.path.join(self.base_dir, f"RPE_party{i}")
            config_file = os.path.join(rpe_dir, "config.toml")
            if not os.path.exists(config_file):
                logger.warning("Config file not found for RPE Party %d: %s" % (i, config_file))
                continue

            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                if "rpe" not in config or "rpe_port" not in config["rpe"]:
                    logger.warning("rpe_port not found in config for RPE Party %d" % i)
                    continue
                port = int(config["rpe"]["rpe_port"].strip("'\""))
            except Exception as e:
                logger.error("Failed to read rpe_port for RPE Party %d: %s" % (i, str(e)))
                continue

            try:
                out = subprocess.run(
                    ["lsof", "-ti", ":%d" % port],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except FileNotFoundError:
                logger.warning("lsof not found; cannot stop RPE by port automatically")
                return
            except Exception as e:
                logger.error("Failed to inspect port %d for RPE Party %d: %s" % (port, i, str(e)))
                continue

            if out.returncode == 0 and out.stdout.strip():
                for pid_str in out.stdout.strip().split():
                    pid = int(pid_str)
                    logger.info("Killing PID %d (listening on port %d, rpe_party%d)" % (pid, port, i))
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            else:
                logger.info("No process found on port %d for rpe_party%d" % (port, i))
  

def main():
    import argparse
    import glob

    parser = argparse.ArgumentParser(description="批量启动多个 RPE")
    parser.add_argument("--num-parties", type=int, required=True, help="参与方数量")
    parser.add_argument("--wait", type=int, default=0, help="等待时间（秒），0 表示持续运行")
    parser.add_argument("--delete-flags-only", action="store_true",
                        help="仅删除各 RPE 目录下 performance_data 中的 rpe_pre_init_ready_*.flag（不启动、不停止进程），用于手动退出 RPE 后清空 flag 以便 performance_test 自动重试")
    parser.add_argument("--base-dir", type=str, default=None, help="项目根目录（默认：performance 的上级）")
    parser.add_argument("--stop", action="store_true", help="仅按端口清理已启动的 RPE 进程")
    
    args = parser.parse_args()
    
    if args.delete_flags_only:
        base_dir = args.base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        n = args.num_parties
        for i in range(1, n + 1):
            perf_data_dir = os.path.join(base_dir, f"RPE_party{i}", "performance_data")
            if os.path.isdir(perf_data_dir):
                for flag_file in glob.glob(os.path.join(perf_data_dir, "rpe_pre_init_ready_*.flag")):
                    try:
                        os.remove(flag_file)
                        logger.info("Removed flag: %s" % flag_file)
                    except Exception as e:
                        logger.warning("Failed to remove flag %s: %s" % (flag_file, e))
        return
    
    starter = RPEStarter(base_dir=args.base_dir, num_parties=args.num_parties)

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
            logger.info("RPEs are running. Press Ctrl+C to stop.")
            while True:
                time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        starter.stop_all()

if __name__ == "__main__":
    main()
