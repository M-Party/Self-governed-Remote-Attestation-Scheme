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
        
        # RPE 基础目录（用于自动发现所有 RPE）
        if rpe_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rpe_base_dir = base_dir
        else:
            # 如果指定了单个 RPE 目录，则只使用该目录
            self.rpe_base_dir = os.path.dirname(rpe_dir) if os.path.isdir(rpe_dir) else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    
    def _discover_rpe_dirs(self):
        """自动发现所有 RPE 目录"""
        rpe_dirs = []
        for path in glob.glob(os.path.join(self.rpe_base_dir, "RPE_party*")):
            if os.path.isdir(path):
                rpe_dirs.append(path)
        if not rpe_dirs:
            # 如果没有找到 RPE_party*，尝试查找单个 RPE 目录
            rpe_dir = os.path.join(self.rpe_base_dir, "RPE")
            if os.path.isdir(rpe_dir):
                rpe_dirs.append(rpe_dir)
        return sorted(rpe_dirs)
    
    def _find_rpe_perf_file(self, rpe_dir=None):
        """查找指定 RPE 目录的 Phase 3 性能文件"""
        if rpe_dir is None:
            rpe_dir = self.rpe_dir if hasattr(self, 'rpe_dir') and self.rpe_dir else None
            if rpe_dir is None:
                # 如果没有指定，查找第一个 RPE 目录
                rpe_dirs = self._discover_rpe_dirs()
                if rpe_dirs:
                    rpe_dir = rpe_dirs[0]
                else:
                    return None
        
        perf_file = os.path.join(rpe_dir, "performance_data", "rpe_phase3_perf_*.json")
        files = glob.glob(perf_file)
        if files:
            return files[0]
        return None
    
    def _find_all_rpe_perf_files(self):
        """查找所有 RPE 的 Phase 3 性能文件"""
        rpe_perf_files = {}
        for rpe_dir in self._discover_rpe_dirs():
            perf_file = self._find_rpe_perf_file(rpe_dir)
            if perf_file:
                # 从文件名中提取 rpe_id
                filename = os.path.basename(perf_file)
                # 格式: rpe_phase3_perf_{rpe_id}.json
                if filename.startswith("rpe_phase3_perf_") and filename.endswith(".json"):
                    rpe_id = filename[16:-5]  # 去掉前缀和后缀
                    rpe_perf_files[rpe_id] = perf_file
        return rpe_perf_files
    
    def _find_ce_perf_file(self, ce_id):
        """查找 CE 性能文件"""
        for ce_dir in self._discover_ce_dirs():
            perf_file = os.path.join(ce_dir, "performance_data", f"ce_perf_{ce_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None
    
    def wait_for_ces_complete(self, ce_ids, timeout=300):
        """等待所有 CE 完成认证"""
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
        # 收集所有 RPE 端数据
        rpe_perf_files = self._find_all_rpe_perf_files()
        rpe_data_dict = {}
        for rpe_id, perf_file in rpe_perf_files.items():
            try:
                with open(perf_file, 'r') as f:
                    rpe_data_dict[rpe_id] = json.load(f)
            except Exception as e:
                logger.warning("Error reading RPE perf file for %s: %s" % (rpe_id, e))
        
        # 如果只有一个 RPE，保持向后兼容性
        rpe_data = rpe_data_dict if len(rpe_data_dict) > 1 else (list(rpe_data_dict.values())[0] if rpe_data_dict else None)
        
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
        注意：此方法不启动 CE，CE 应该由 start_multi_ce.py 启动
        concurrent: 仅用于标识测试模式，不影响实际启动逻辑
        """
        logger.info("=" * 60)
        logger.info("Starting Phase 3 performance test with %d CEs" % num_ces)
        logger.info("Note: CEs should be started separately using start_multi_ce.py")
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
        
        # 清理所有 RPE 性能数据
        for rpe_dir in self._discover_rpe_dirs():
            rpe_perf_data_dir = os.path.join(rpe_dir, "performance_data")
            if os.path.exists(rpe_perf_data_dir):
                for perf_file in glob.glob(os.path.join(rpe_perf_data_dir, "rpe_phase3_perf_*.json")):
                    try:
                        os.remove(perf_file)
                        logger.debug("Removed RPE perf file: %s" % perf_file)
                    except Exception as e:
                        logger.warning("Failed to remove RPE perf file %s: %s" % (perf_file, e))
        
        # 生成 CE ID 列表
        ce_ids = [f"ce-{i+1}" for i in range(num_ces)]
        ce_dirs = self._discover_ce_dirs()[:num_ces]
        
        if len(ce_dirs) < num_ces:
            logger.error("Not enough CE directories found. Need %d, found %d" % (num_ces, len(ce_dirs)))
            return None
        
        # 等待所有 CE 完成认证
        logger.info("Waiting for all CEs to complete authentication...")
        success = self.wait_for_ces_complete(ce_ids, timeout=300)
        if not success:
            logger.error("Test failed: not all CEs completed authentication")
            return None
        
        # 收集性能数据
        rpe_data, ce_data = self.collect_performance_data(ce_ids)
        
        # 从 RPE 数据中提取所有 CE 的认证时间（auth_duration）
        rpe_auth_durations = []
        all_rpe_ce_auths = []
        first_auth_start = None
        last_auth_end = None
        
        # 聚合所有 RPE 的认证数据
        if rpe_data:
            if isinstance(rpe_data, dict) and "ce_authentications" in rpe_data:
                # 单个 RPE 的情况
                all_rpe_ce_auths = rpe_data["ce_authentications"]
            elif isinstance(rpe_data, dict):
                # 多个 RPE 的情况（字典，key 是 rpe_id）
                for rpe_id, rpe_info in rpe_data.items():
                    if isinstance(rpe_info, dict) and "ce_authentications" in rpe_info:
                        all_rpe_ce_auths.extend(rpe_info["ce_authentications"])
        
        # 收集每个 CE 的 auth_duration 和计算总时间
        if all_rpe_ce_auths:
            # 收集所有 auth_duration
            for auth in all_rpe_ce_auths:
                if auth.get("auth_duration") is not None:
                    rpe_auth_durations.append(auth["auth_duration"])
            
            # 找到第一个 auth_start 和最后一个 auth_end
            valid_auths = [auth for auth in all_rpe_ce_auths 
                          if auth.get("auth_start") is not None and auth.get("auth_end") is not None]
            if valid_auths:
                first_auth_start = min(auth.get("auth_start", float('inf')) for auth in valid_auths)
                last_auth_end = max(auth.get("auth_end", 0) for auth in valid_auths)
        
        # 计算平均 auth_duration
        avg_auth_duration = sum(rpe_auth_durations) / len(rpe_auth_durations) if rpe_auth_durations else 0
        
        # 计算总时间（第一个 auth_start 到最后一个 auth_end）
        rpe_total_time = None
        throughput = 0
        if first_auth_start is not None and last_auth_end is not None and first_auth_start != float('inf') and last_auth_end > 0:
            rpe_total_time = last_auth_end - first_auth_start
            # 吞吐量 = CE数量 / RPE总认证时间 * 60
            throughput = (num_ces / rpe_total_time) * 60 if rpe_total_time > 0 else 0
        
        # 如果 RPE 数据不可用
        if not rpe_auth_durations:
            logger.warning("RPE performance data not available, no authentication records found")
            rpe_total_time = 0
        
        result = {
            "num_ces": num_ces,
            "concurrent": concurrent,
            "ce_ids": ce_ids,
            "first_auth_start": first_auth_start,
            "last_auth_end": last_auth_end,
            "rpe_total_time": rpe_total_time,  # 第一个 auth_start 到最后一个 auth_end 的总时间
            "throughput_per_minute": throughput,
            "individual_perf": ce_data,
            "rpe_perf": rpe_data,
            "statistics": {
                "avg_auth_duration": avg_auth_duration,  # N 个 CE 的平均 auth_duration
                "auth_duration": {
                    "avg": avg_auth_duration,
                    "min": min(rpe_auth_durations) if rpe_auth_durations else 0,
                    "max": max(rpe_auth_durations) if rpe_auth_durations else 0,
                    "count": len(rpe_auth_durations)  # 实际收集到的认证记录数
                }
            }
        }
        
        # 保存结果
        result_file = os.path.join(self.perf_dir, f"phase3_test_result_{num_ces}ces.json")
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        logger.info("=" * 60)
        logger.info("Test Results for %d CEs:" % num_ces)
        if first_auth_start is not None:
            logger.info("  First CE auth_start: %.3f" % first_auth_start)
        if last_auth_end is not None:
            logger.info("  Last CE auth_end: %.3f" % last_auth_end)
        if rpe_total_time is not None and rpe_total_time > 0:
            logger.info("  Total Time (first auth_start to last auth_end): %.3f seconds" % rpe_total_time)
        logger.info("  Throughput: %.2f CEs/minute" % throughput)
        if rpe_auth_durations:
            logger.info("  Average Auth Duration (RPE-side): %.3f seconds" % avg_auth_duration)
            logger.info("  Auth Duration - Min: %.3f, Max: %.3f, Count: %d" % (
                result["statistics"]["auth_duration"]["min"],
                result["statistics"]["auth_duration"]["max"],
                result["statistics"]["auth_duration"]["count"]
            ))
        else:
            logger.warning("  No RPE authentication data found")
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
                "First Auth Start",
                "Last Auth End",
                "Total Time (s)",
                "Avg Auth Duration (s)",
                "Min Auth Duration (s)",
                "Max Auth Duration (s)",
                "Auth Count",
                "Throughput (CEs/min)"
            ])
            
            # 写入数据
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_duration"]
                rpe_total_time = result.get("rpe_total_time", 0)
                first_start = result.get("first_auth_start", 0)
                last_end = result.get("last_auth_end", 0)
                
                writer.writerow([
                    num_ces,
                    "%.3f" % first_start if first_start else "N/A",
                    "%.3f" % last_end if last_end else "N/A",
                    "%.3f" % rpe_total_time if rpe_total_time else "N/A",
                    "%.3f" % stats.get("avg", 0),
                    "%.3f" % stats.get("min", 0),
                    "%.3f" % stats.get("max", 0),
                    stats.get("count", 0),
                    "%.2f" % result["throughput_per_minute"]
                ])
        
        # 生成文本报告
        report_file = os.path.join(self.perf_dir, "phase3_summary_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("Phase 3 Performance Test Summary (RPE Authentication of CEs)\n")
            f.write("=" * 100 + "\n\n")
            
            f.write("Number | First Auth  | Last Auth   | Total Time | Avg Auth   | Min Auth   | Max Auth   | Count | Throughput\n")
            f.write("of CEs | Start        | End          | (s)        | Duration(s)| Duration(s)| Duration(s)|       | (CEs/min)\n")
            f.write("-" * 100 + "\n")
            
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_duration"]
                rpe_total_time = result.get("rpe_total_time", 0)
                first_start = result.get("first_auth_start", 0)
                last_end = result.get("last_auth_end", 0)
                
                f.write("%6d | %12.3f | %12.3f | %10.3f | %10.3f | %10.3f | %10.3f | %5d | %10.2f\n" % (
                    num_ces,
                    first_start if first_start else 0,
                    last_end if last_end else 0,
                    rpe_total_time if rpe_total_time else 0,
                    stats.get("avg", 0),
                    stats.get("min", 0),
                    stats.get("max", 0),
                    stats.get("count", 0),
                    result["throughput_per_minute"]
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