#!/usr/bin/env python3
"""
Phase 3 性能测试脚本
测试 RPE 认证 CE 的时间随 CE 数量变化的情况，以及吞吐量
"""
import json
import time
import os
import sys
import subprocess
import glob
import logging
import csv
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Phase3PerformanceTest:
    def __init__(self, perf_dir="./performance_data", rpe_dir=None, ce_base_dir=None):
        self.perf_dir = perf_dir
        os.makedirs(self.perf_dir, exist_ok=True)
        
        # 自动发现 RPE 目录
        if rpe_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            # 查找第一个 RPE_party* 目录
            for path in glob.glob(os.path.join(base_dir, "RPE_party*")):
                if os.path.isdir(path):
                    self.rpe_dir = path
                    break
            else:
                self.rpe_dir = os.path.join(base_dir, "RPE")
        else:
            self.rpe_dir = rpe_dir
            
        # CE 基础目录
        if ce_base_dir is None:
            self.ce_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            self.ce_base_dir = ce_base_dir
    
    def _discover_ce_dirs(self):
        """自动发现 CE 目录"""
        ce_dirs = []
        for path in glob.glob(os.path.join(self.ce_base_dir, "CE_party*")):
            if os.path.isdir(path):
                ce_dirs.append(path)
        return sorted(ce_dirs)
    
    def _find_rpe_perf_file(self):
        """查找 RPE Phase 3 性能文件"""
        perf_file = os.path.join(self.rpe_dir, "performance_data", "rpe_phase3_perf_*.json")
        files = glob.glob(perf_file)
        if files:
            return files[0]
        return None
    
    def _find_ce_perf_file(self, ce_id):
        """查找 CE 性能文件"""
        for ce_dir in self._discover_ce_dirs():
            perf_file = os.path.join(ce_dir, "performance_data", f"ce_perf_{ce_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None
    
    def wait_for_ces_complete(self, ce_ids, timeout=300):
        """等待所有 CE 完成认证"""
        logger.info("Waiting for all CEs to complete authentication...")
        start_time = time.time()
        completed_ces = set()
        
        while len(completed_ces) < len(ce_ids):
            if time.time() - start_time > timeout:
                logger.error("Timeout waiting for CEs to complete")
                return False
                
            for ce_id in ce_ids:
                if ce_id in completed_ces:
                    continue
                    
                perf_file = self._find_ce_perf_file(ce_id)
                if perf_file and os.path.exists(perf_file):
                    try:
                        with open(perf_file, 'r') as f:
                            perf_data = json.load(f)
                            if perf_data.get("auth_end") is not None:
                                completed_ces.add(ce_id)
                                logger.info("CE %s completed authentication" % ce_id)
                    except Exception as e:
                        logger.warning("Error reading perf file for %s: %s" % (ce_id, e))
            
            time.sleep(1)
        
        logger.info("All CEs completed authentication!")
        return True
    
    def collect_performance_data(self, ce_ids):
        """收集性能数据"""
        # 收集 RPE 端数据
        rpe_perf_file = self._find_rpe_perf_file()
        rpe_data = None
        if rpe_perf_file:
            try:
                with open(rpe_perf_file, 'r') as f:
                    rpe_data = json.load(f)
            except Exception as e:
                logger.warning("Error reading RPE perf file: %s" % e)
        
        # 收集 CE 端数据
        ce_data = {}
        for ce_id in ce_ids:
            perf_file = self._find_ce_perf_file(ce_id)
            if perf_file and os.path.exists(perf_file):
                try:
                    with open(perf_file, 'r') as f:
                        ce_data[ce_id] = json.load(f)
                except Exception as e:
                    logger.warning("Error reading perf file for %s: %s" % (ce_id, e))
        
        return rpe_data, ce_data
    
    def run_test(self, num_ces, concurrent=False):
        """
        运行性能测试
        concurrent: True 表示并发启动所有 CE，False 表示顺序启动
        """
        logger.info("=" * 60)
        logger.info("Starting Phase 3 performance test with %d CEs (concurrent=%s)" % (num_ces, concurrent))
        logger.info("=" * 60)
        
        # 清理之前的性能数据
        for ce_dir in self._discover_ce_dirs():
            perf_data_dir = os.path.join(ce_dir, "performance_data")
            if os.path.exists(perf_data_dir):
                for perf_file in glob.glob(os.path.join(perf_data_dir, "ce_perf_*.json")):
                    try:
                        os.remove(perf_file)
                    except:
                        pass
        
        # 清理 RPE 性能数据
        rpe_perf_data_dir = os.path.join(self.rpe_dir, "performance_data")
        if os.path.exists(rpe_perf_data_dir):
            for perf_file in glob.glob(os.path.join(rpe_perf_data_dir, "rpe_phase3_perf_*.json")):
                try:
                    os.remove(perf_file)
                except:
                    pass
        
        # 生成 CE ID 列表
        ce_ids = [f"ce-{i+1}" for i in range(num_ces)]
        ce_dirs = self._discover_ce_dirs()[:num_ces]
        
        if len(ce_dirs) < num_ces:
            logger.error("Not enough CE directories found. Need %d, found %d" % (num_ces, len(ce_dirs)))
            return None
        
        # 记录系统级开始时间
        system_start = time.time()
        
        # 启动所有 CE
        processes = []
        for i, ce_dir in enumerate(ce_dirs):
            ce_id = ce_ids[i]
            startup_script = os.path.join(ce_dir, "startup.sh")
            if not os.path.exists(startup_script):
                logger.warning("Startup script not found: %s" % startup_script)
                continue
            
            log_dir = os.path.join(ce_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            try:
                log_file = open(os.path.join(log_dir, f"ce_party{i+1}.log"), "w")
                process = subprocess.Popen(
                    ["bash", startup_script, "start"],
                    cwd=ce_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT
                )
                processes.append((ce_id, process, log_file))
                logger.info("CE %s started (PID: %d)" % (ce_id, process.pid))
                
                if not concurrent:
                    # 顺序启动：等待当前 CE 完成认证
                    logger.info("Waiting for CE %s to complete..." % ce_id)
                    self.wait_for_ces_complete([ce_id], timeout=300)
                    
            except Exception as e:
                logger.error("Failed to start CE %s: %s" % (ce_id, str(e)))
        
        # 如果是并发模式，等待所有 CE 完成
        if concurrent:
            success = self.wait_for_ces_complete(ce_ids, timeout=300)
            if not success:
                logger.error("Test failed: not all CEs completed authentication")
                return None
        
        # 记录系统级结束时间
        system_end = time.time()
        system_total_time = system_end - system_start
        
        # 收集性能数据
        rpe_data, ce_data = self.collect_performance_data(ce_ids)
        
        # 计算统计信息
        ce_auth_times = []
        for ce_id in ce_ids:
            if ce_id in ce_data and ce_data[ce_id].get("auth_duration"):
                ce_auth_times.append(ce_data[ce_id]["auth_duration"])
        
        # 计算吞吐量（每分钟认证的 CE 数量）
        throughput = (num_ces / system_total_time) * 60 if system_total_time > 0 else 0
        
        result = {
            "num_ces": num_ces,
            "concurrent": concurrent,
            "ce_ids": ce_ids,
            "system_total_time": system_total_time,
            "system_start": system_start,
            "system_end": system_end,
            "throughput_per_minute": throughput,
            "individual_perf": ce_data,
            "rpe_perf": rpe_data,
            "statistics": {
                "auth_time": {
                    "avg": sum(ce_auth_times) / len(ce_auth_times) if ce_auth_times else 0,
                    "min": min(ce_auth_times) if ce_auth_times else 0,
                    "max": max(ce_auth_times) if ce_auth_times else 0
                }
            }
        }
        
        # 保存结果
        result_file = os.path.join(self.perf_dir, f"phase3_test_result_{num_ces}ces.json")
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        logger.info("=" * 60)
        logger.info("Test Results for %d CEs:" % num_ces)
        logger.info("  System Total Time: %.3f seconds" % system_total_time)
        logger.info("  Throughput: %.2f CEs/minute" % throughput)
        logger.info("  Auth Time - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["auth_time"]["avg"],
            result["statistics"]["auth_time"]["min"],
            result["statistics"]["auth_time"]["max"]
        ))
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        
        return result
    
    def run_series(self, start=1, end=10, concurrent=False):
        """运行一系列测试"""
        all_results = []
        
        for num_ces in range(start, end + 1):
            result = self.run_test(num_ces, concurrent=concurrent)
            if result:
                all_results.append(result)
            time.sleep(5)  # 测试间隔
        
        # 生成汇总报告
        self.generate_summary_report(all_results)
        
        return all_results
    
    def generate_summary_report(self, all_results):
        """生成汇总报告"""
        import csv
        
        # 生成 CSV 文件
        csv_file = os.path.join(self.perf_dir, "phase3_summary_report.csv")
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # 写入表头
            writer.writerow([
                "Number of CEs",
                "System Total Time (s)",
                "Throughput (CEs/min)",
                "Auth Time Avg (s)",
                "Auth Time Min (s)",
                "Auth Time Max (s)"
            ])
            
            # 写入数据
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_time"]
                
                writer.writerow([
                    num_ces,
                    "%.3f" % result["system_total_time"],
                    "%.2f" % result["throughput_per_minute"],
                    "%.3f" % stats["avg"],
                    "%.3f" % stats["min"],
                    "%.3f" % stats["max"]
                ])
        
        # 生成文本报告
        report_file = os.path.join(self.perf_dir, "phase3_summary_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("Phase 3 Performance Test Summary (RPE Authentication of CEs)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Number of CEs | System Total | Throughput | Auth Avg | Auth Min | Auth Max\n")
            f.write("-" * 80 + "\n")
            
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_time"]
                
                f.write("%13d | %12.3f | %9.2f | %8.3f | %8.3f | %8.3f\n" % (
                    num_ces,
                    result["system_total_time"],
                    result["throughput_per_minute"],
                    stats["avg"], stats["min"], stats["max"]
                ))
        
        logger.info("Summary report (CSV) saved to: %s" % csv_file)
        logger.info("Summary report (TXT) saved to: %s" % report_file)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 3 Performance Test")
    parser.add_argument("--start", type=int, default=1, help="Starting number of CEs")
    parser.add_argument("--end", type=int, default=10, help="Ending number of CEs")
    parser.add_argument("--single", type=int, default=None, help="Test with a single number of CEs")
    parser.add_argument("--concurrent", action="store_true", help="Start CEs concurrently")
    parser.add_argument("--perf-dir", type=str, default="./performance_data", help="Performance data directory")
    parser.add_argument("--rpe-dir", type=str, default=None, help="RPE directory")
    parser.add_argument("--ce-base-dir", type=str, default=None, help="CE base directory")
    
    args = parser.parse_args()
    
    test = Phase3PerformanceTest(
        perf_dir=args.perf_dir,
        rpe_dir=args.rpe_dir,
        ce_base_dir=args.ce_base_dir
    )
    
    if args.single:
        test.run_test(args.single, concurrent=args.concurrent)
    else:
        test.run_series(start=args.start, end=args.end, concurrent=args.concurrent)