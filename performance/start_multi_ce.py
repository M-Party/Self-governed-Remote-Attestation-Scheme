#!/usr/bin/env python3
"""
批量启动多个 CE 实例
"""
import os
import sys
import subprocess
import logging
import argparse
import glob

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class MultiCEStarter:
    def __init__(self, base_dir=None, num_parties=1):
        if base_dir is None:
            self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            self.base_dir = base_dir
        self.num_parties = num_parties
        self.processes = []
    
    def start_all(self, concurrent=True):
        """启动所有 CE（并行或顺序）"""
        logger.info("Starting CEs...")
        
        # 收集所有需要启动的 CE 信息
        ce_configs = []
        for i in range(1, self.num_parties + 1):
            ce_dir = os.path.join(self.base_dir, f"CE_party{i}")
            if not os.path.exists(ce_dir):
                logger.warning("CE Party %d not found: %s" % (i, ce_dir))
                continue
            
            startup_script = os.path.join(ce_dir, "startup.sh")
            if not os.path.exists(startup_script):
                logger.warning("Startup script not found: %s" % startup_script)
                continue
            
            log_dir = os.path.join(ce_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            ce_configs.append((i, ce_dir, log_dir, startup_script))
        
        # 清理性能文件
        logger.info("Cleaning up performance data files...")
        for i, ce_dir, log_dir, startup_script in ce_configs:
            perf_data_dir = os.path.join(ce_dir, "performance_data")
            if os.path.exists(perf_data_dir):
                for perf_file in glob.glob(os.path.join(perf_data_dir, "ce_perf_*.json")):
                    try:
                        os.remove(perf_file)
                        logger.debug("Removed performance file: %s" % perf_file)
                    except Exception as e:
                        logger.warning("Failed to remove performance file %s: %s" % (perf_file, e))
        
        # 启动所有 CE
        if concurrent:
            # 并发启动：先创建所有进程，然后一次性启动
            logger.info("Starting %d CEs concurrently..." % len(ce_configs))
            processes_to_start = []
            
            for i, ce_dir, log_dir, startup_script in ce_configs:
                try:
                    ce_id = f"ce-{i}"
                    log_file = open(os.path.join(log_dir, f"ce_party{i}.log"), "w")
                    processes_to_start.append((i, ce_id, ce_dir, log_dir, startup_script, log_file))
                except Exception as e:
                    logger.error("Failed to prepare CE Party %d: %s" % (i, str(e)))
            
            # 一次性启动所有进程（减少启动时间差异）
            for i, ce_id, ce_dir, log_dir, startup_script, log_file in processes_to_start:
                try:
                    process = subprocess.Popen(
                        ["bash", startup_script, "start"],
                        cwd=ce_dir,
                        stdout=log_file,
                        stderr=subprocess.STDOUT
                    )
                    self.processes.append((f"ce_party{i}", process, log_file))
                    logger.info("CE Party %d (%s) started (PID: %d)" % (i, ce_id, process.pid))
                except Exception as e:
                    logger.error("Failed to start CE Party %d: %s" % (i, str(e)))
                    log_file.close()
            
            if self.processes:
                logger.info("All %d CEs started concurrently. Waiting for them to initialize..." % len(self.processes))
        else:
            # 顺序启动：等待当前进程完成
            logger.info("Starting CEs sequentially...")
            for i, ce_dir, log_dir, startup_script in ce_configs:
                try:
                    ce_id = f"ce-{i}"
                    log_file = open(os.path.join(log_dir, f"ce_party{i}.log"), "w")
                    process = subprocess.Popen(
                        ["bash", startup_script, "start"],
                        cwd=ce_dir,
                        stdout=log_file,
                        stderr=subprocess.STDOUT
                    )
                    self.processes.append((f"ce_party{i}", process, log_file))
                    logger.info("CE Party %d (%s) started (PID: %d)" % (i, ce_id, process.pid))
                    process.wait()
                except Exception as e:
                    logger.error("Failed to start CE Party %d: %s" % (i, str(e)))
    
    def stop_all(self):
        """停止所有 CE"""
        logger.info("Stopping all CEs...")
        for name, process, log_file in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
                log_file.close()
                logger.info("CE %s stopped" % name)
            except subprocess.TimeoutExpired:
                process.kill()
                log_file.close()
                logger.warning("CE %s force killed" % name)
            except Exception as e:
                logger.error("Error stopping CE %s: %s" % (name, str(e)))
        self.processes = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start multiple CE instances")
    parser.add_argument("--num-parties", type=int, default=1, help="Number of CE parties to start")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    parser.add_argument("--sequential", action="store_true", help="Start CEs sequentially")
    
    args = parser.parse_args()
    
    starter = MultiCEStarter(base_dir=args.base_dir, num_parties=args.num_parties)
    
    try:
        starter.start_all(concurrent=not args.sequential)
        # 保持运行直到用户中断
        import signal
        def signal_handler(sig, frame):
            logger.info("Received interrupt signal, stopping all CEs...")
            starter.stop_all()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 等待所有进程
        for name, process, log_file in starter.processes:
            process.wait()
            log_file.close()
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping all CEs...")
        starter.stop_all()