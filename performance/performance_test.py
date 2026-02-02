#!/usr/bin/env python3
"""
RPE 初始化性能测试脚本
- Phase1 测试：先启动 RPO 再启动 RPE，统计 Phase1 时间随参与方数量变化
- Phase2 测试：先启动 RPE，等所有 RPE 预初始化完成后给出信号再启动 RPO，统计 Phase2 时间随参与方数量变化
"""
import json
import time
import os
import sys
import signal
import subprocess
import glob
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# 用于在脚本内 import start_multi_rpe / start_multi_rpo
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)


class RPEPerformanceTest:
    def __init__(self, max_rpe_count=5, perf_dir="./performance_data", rpe_dirs=None,
                 test_mode="phase1", base_dir=None, stop_after_test=True):
        self.max_rpe_count = max_rpe_count
        self.perf_dir = perf_dir
        self.test_mode = test_mode  # "phase1" or "phase2"
        self.base_dir = base_dir or os.path.dirname(_script_dir)
        self.stop_after_test = stop_after_test
        os.makedirs(self.perf_dir, exist_ok=True)
        
        # 配置 RPE 目录列表，例如 ["../RPE", "../RPE1", "../RPE2"]
        if rpe_dirs is None:
            self.rpe_dirs = self._discover_rpe_dirs()
        else:
            self.rpe_dirs = rpe_dirs

        self.rpo_starter = None
        self.rpe_starter = None
    
    def _discover_rpe_dirs(self):
        """自动发现 RPE 目录"""
        base_dir = self.base_dir
        rpe_dirs = []
        for path in glob.glob(os.path.join(base_dir, "RPE_party*")):
            if os.path.isdir(path):
                perf_data_dir = os.path.join(path, "performance_data")
                if os.path.exists(perf_data_dir):
                    rpe_dirs.append(path)
        return rpe_dirs if rpe_dirs else [os.path.join(base_dir, "RPE")]
        
    def wait_for_all_rpes_pre_init_ready(self, rpe_ids, timeout=120):
        """
        等待所有 RPE 预初始化完成（密钥生成 + client 初始化，尚未连 RPO）
        用于 Phase2 测试：先启 RPE，等此条件满足后再启 RPO
        """
        logger.info("Waiting for all RPEs to be pre-init ready (keys + client init)...")
        start_time = time.time()
        ready = set()
        while len(ready) < len(rpe_ids):
            if time.time() - start_time > timeout:
                logger.error("Timeout waiting for RPEs pre-init ready (%d/%d)" % (len(ready), len(rpe_ids)))
                return False
            for rpe_id in rpe_ids:
                if rpe_id in ready:
                    continue
                for rpe_dir in self.rpe_dirs:
                    flag_file = os.path.join(rpe_dir, "performance_data", "rpe_pre_init_ready_%s.flag" % rpe_id)
                    if os.path.isfile(flag_file):
                        ready.add(rpe_id)
                        logger.info("RPE %s pre-init ready" % rpe_id)
                        break
            time.sleep(0.2)
        logger.info("All %d RPE(s) pre-init ready. You can start RPO now." % len(rpe_ids))
        return True

    def wait_for_all_rpes_complete(self, rpe_ids, timeout=300):
        """
        等待所有 RPE 完成初始化（Phase 2 完成）
        如果性能文件被删除，会重新从所有 RPE 目录查找
        """
        logger.info("Waiting for all RPEs to complete initialization...")
        start_time = time.time()
        completed_rpes = set()
        # 记录每个 RPE 找到的性能文件路径，用于检测文件是否被删除
        rpe_perf_files = {}
        
        while len(completed_rpes) < len(rpe_ids):
            if time.time() - start_time > timeout:
                logger.error("Timeout waiting for RPEs to complete")
                return False
                
            for rpe_id in rpe_ids:
                # 每次循环都重新从所有 RPE 目录查找性能文件
                perf_file = self._find_perf_file(rpe_id)
                
                # 如果之前找到的文件被删除了，从 completed_rpes 中移除，重新查找
                if rpe_id in completed_rpes:
                    if rpe_id in rpe_perf_files:
                        old_file = rpe_perf_files[rpe_id]
                        if not os.path.exists(old_file):
                            logger.warning("Performance file for RPE %s was deleted, re-searching..." % rpe_id)
                            completed_rpes.remove(rpe_id)
                            del rpe_perf_files[rpe_id]
                            # 继续查找新的文件
                            perf_file = self._find_perf_file(rpe_id)
                    else:
                        # 如果之前没有记录文件路径，重新查找
                        perf_file = self._find_perf_file(rpe_id)
                
                # 如果找到了性能文件
                if perf_file and os.path.exists(perf_file):
                    try:
                        with open(perf_file, 'r') as f:
                            perf_data = json.load(f)
                            if perf_data.get("timestamps", {}).get("init_complete") is not None:
                                # 记录找到的文件路径
                                rpe_perf_files[rpe_id] = perf_file
                                if rpe_id not in completed_rpes:
                                    completed_rpes.add(rpe_id)
                                    logger.info("RPE %s completed initialization" % rpe_id)
                    except Exception as e:
                        logger.warning("Error reading perf file for %s: %s" % (rpe_id, e))
            
            time.sleep(1)
        
        logger.info("All RPEs completed initialization!")
        return True

    def _find_perf_file(self, rpe_id):
        """从所有 RPE 目录中查找性能文件"""
        for rpe_dir in self.rpe_dirs:
            perf_file = os.path.join(rpe_dir, "performance_data", f"rpe_perf_{rpe_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None
    
    def collect_performance_data(self, rpe_ids):
        """
        收集所有 RPE 的性能数据
        """
        all_perf_data = {}
        system_start_time = None
        system_end_time = None
        
        for rpe_id in rpe_ids:
            perf_file = self._find_perf_file(rpe_id)
            if perf_file and os.path.exists(perf_file):
                try:
                    with open(perf_file, 'r') as f:
                        perf_data = json.load(f)
                        all_perf_data[rpe_id] = perf_data
                        
                        # 计算系统级时间范围
                        timestamps = perf_data.get("timestamps", {})
                        if timestamps.get("init_start"):
                            if system_start_time is None or timestamps["init_start"] < system_start_time:
                                system_start_time = timestamps["init_start"]
                        if timestamps.get("init_complete"):
                            if system_end_time is None or timestamps["init_complete"] > system_end_time:
                                system_end_time = timestamps["init_complete"]
                except Exception as e:
                    logger.error("Error reading perf file for %s: %s" % (rpe_id, e))
        
        return all_perf_data, system_start_time, system_end_time
    
    def _cleanup_perf_files(self):
        """清理所有 RPE 目录下的性能数据文件"""
        for rpe_dir in self.rpe_dirs:
            perf_data_dir = os.path.join(rpe_dir, "performance_data")
            if os.path.exists(perf_data_dir):
                for perf_file in glob.glob(os.path.join(perf_data_dir, "rpe_perf_*.json")):
                    try:
                        os.remove(perf_file)
                    except Exception:
                        pass
                for flag_file in glob.glob(os.path.join(perf_data_dir, "rpe_pre_init_ready_*.flag")):
                    try:
                        os.remove(flag_file)
                    except Exception:
                        pass

    def run_test_phase1(self, num_rpes):
        """Phase1 测试：先启动 RPO 再启动 RPE，统计 Phase1 时间"""
        from start_multi_rpo import RPOStarter
        from start_multi_rpe import RPEStarter
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        self._cleanup_perf_files()
        logger.info("Phase1 test: Starting RPO first, then RPE...")
        self.rpo_starter = RPOStarter(base_dir=self.base_dir, num_parties=num_rpes)
        self.rpo_starter.start_all()
        time.sleep(5)
        self.rpe_starter = RPEStarter(base_dir=self.base_dir, num_parties=num_rpes)
        self.rpe_starter.start_all()
        success = self.wait_for_all_rpes_complete(rpe_ids)
        if not success:
            logger.error("Phase1 test failed: not all RPEs completed initialization")
            if self.stop_after_test:
                if self.rpe_starter:
                    self.rpe_starter.stop_all()
                if self.rpo_starter:
                    self.rpo_starter.stop_all()
            return None
        result = self._collect_and_report(num_rpes, rpe_ids)
        if self.stop_after_test:
            if self.rpe_starter:
                self.rpe_starter.stop_all()
            if self.rpo_starter:
                self.rpo_starter.stop_all()
        return result

    def run_test_phase2(self, num_rpes):
        """Phase2 测试：先启动 RPE，等所有 RPE 预初始化完成后启动 RPO，统计 Phase2 时间"""
        from start_multi_rpo import RPOStarter
        from start_multi_rpe import RPEStarter
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        self._cleanup_perf_files()
        logger.info("Phase2 test: Starting RPE first, waiting for pre-init ready, then RPO...")
        self.rpe_starter = RPEStarter(base_dir=self.base_dir, num_parties=num_rpes)
        self.rpe_starter.start_all()
        if not self.wait_for_all_rpes_pre_init_ready(rpe_ids):
            logger.error("Phase2 test failed: not all RPEs became pre-init ready")
            if self.stop_after_test and self.rpe_starter:
                self.rpe_starter.stop_all()
            return None
        logger.info("All RPEs pre-init ready. Starting RPO...")
        self.rpo_starter = RPOStarter(base_dir=self.base_dir, num_parties=num_rpes)
        self.rpo_starter.start_all()
        success = self.wait_for_all_rpes_complete(rpe_ids)
        if not success:
            logger.error("Phase2 test failed: not all RPEs completed initialization")
            if self.stop_after_test:
                if self.rpe_starter:
                    self.rpe_starter.stop_all()
                if self.rpo_starter:
                    self.rpo_starter.stop_all()
            return None
        result = self._collect_and_report(num_rpes, rpe_ids)
        if self.stop_after_test:
            if self.rpe_starter:
                self.rpe_starter.stop_all()
            if self.rpo_starter:
                self.rpo_starter.stop_all()
        return result

    def _collect_and_report(self, num_rpes, rpe_ids):
        """收集性能数据并生成单次测试结果（不负责启动/停止）"""
        all_perf_data, earliest_start, latest_end = self.collect_performance_data(rpe_ids)
        if earliest_start and latest_end:
            system_total_time = latest_end - earliest_start
        else:
            system_total_time = None
        phase1_times = []
        phase2_times = []
        total_times = []
        for rpe_id, perf_data in all_perf_data.items():
            durations = perf_data.get("durations", {})
            if durations.get("phase1"):
                phase1_times.append(durations["phase1"])
            if durations.get("phase2"):
                phase2_times.append(durations["phase2"])
            if durations.get("total"):
                total_times.append(durations["total"])
        result = {
            "num_rpes": num_rpes,
            "rpe_ids": rpe_ids,
            "system_total_time": system_total_time,
            "system_start": earliest_start,
            "system_end": latest_end,
            "individual_perf": all_perf_data,
            "statistics": {
                "phase1": {
                    "avg": sum(phase1_times) / len(phase1_times) if phase1_times else 0,
                    "min": min(phase1_times) if phase1_times else 0,
                    "max": max(phase1_times) if phase1_times else 0
                },
                "phase2": {
                    "avg": sum(phase2_times) / len(phase2_times) if phase2_times else 0,
                    "min": min(phase2_times) if phase2_times else 0,
                    "max": max(phase2_times) if phase2_times else 0
                },
                "total": {
                    "avg": sum(total_times) / len(total_times) if total_times else 0,
                    "min": min(total_times) if total_times else 0,
                    "max": max(total_times) if total_times else 0
                }
            }
        }
        result_file = os.path.join(self.perf_dir, "test_result_%drpes.json" % num_rpes)
        with open(result_file, "w") as f:
            json.dump(result, f, indent=2)
        logger.info("=" * 60)
        logger.info("Test Results for %d RPEs (%s):" % (num_rpes, self.test_mode))
        if system_total_time is not None:
            logger.info("  System Total Time: %.3f seconds" % system_total_time)
        logger.info("  Phase 1 - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase1"]["avg"],
            result["statistics"]["phase1"]["min"],
            result["statistics"]["phase1"]["max"]
        ))
        logger.info("  Phase 2 - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2"]["avg"],
            result["statistics"]["phase2"]["min"],
            result["statistics"]["phase2"]["max"]
        ))
        logger.info("  Total (Individual) - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["total"]["avg"],
            result["statistics"]["total"]["min"],
            result["statistics"]["total"]["max"]
        ))
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        return result

    def run_test(self, num_rpes):
        """
        运行指定数量 RPE 的性能测试
        Phase1：先 RPO 再 RPE，统计 Phase1 时间
        Phase2：先 RPE，等预初始化完成后启 RPO，统计 Phase2 时间
        """
        logger.info("=" * 60)
        logger.info("Starting %s performance test with %d RPEs" % (self.test_mode, num_rpes))
        logger.info("=" * 60)
        if self.test_mode == "phase2":
            return self.run_test_phase2(num_rpes)
        return self.run_test_phase1(num_rpes)

    def _run_test_legacy(self, num_rpes):
        """仅等待已有 RPE 完成初始化并收集数据（不启动 RPO/RPE），用于兼容"""
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        self._cleanup_perf_files()
        success = self.wait_for_all_rpes_complete(rpe_ids)
        if not success:
            logger.error("Test failed: not all RPEs completed initialization")
            return None
        return self._collect_and_report(num_rpes, rpe_ids)

    def run_test_original_collect_only(self, num_rpes):
        """
        原逻辑：不启动 RPO/RPE，仅等待所有 RPE 完成初始化并收集数据
        （保留用于手动启动 RPO/RPE 的场景）
        """
        logger.info("=" * 60)
        logger.info("Starting performance test with %d RPEs (collect only, no start)" % num_rpes)
        logger.info("=" * 60)
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        system_start = time.time()
        success = self.wait_for_all_rpes_complete(rpe_ids)
        if not success:
            logger.error("Test failed: not all RPEs completed initialization")
            return None
        system_end = time.time()
        all_perf_data, earliest_start, latest_end = self.collect_performance_data(rpe_ids)
        if earliest_start and latest_end:
            system_total_time = latest_end - earliest_start
        else:
            system_total_time = system_end - system_start
        phase1_times = []
        phase2_times = []
        total_times = []
        for rpe_id, perf_data in all_perf_data.items():
            durations = perf_data.get("durations", {})
            if durations.get("phase1"):
                phase1_times.append(durations["phase1"])
            if durations.get("phase2"):
                phase2_times.append(durations["phase2"])
            if durations.get("total"):
                total_times.append(durations["total"])
        result = {
            "num_rpes": num_rpes,
            "rpe_ids": rpe_ids,
            "system_total_time": system_total_time,
            "system_start": earliest_start,
            "system_end": latest_end,
            "individual_perf": all_perf_data,
            "statistics": {
                "phase1": {"avg": sum(phase1_times) / len(phase1_times) if phase1_times else 0,
                          "min": min(phase1_times) if phase1_times else 0,
                          "max": max(phase1_times) if phase1_times else 0},
                "phase2": {"avg": sum(phase2_times) / len(phase2_times) if phase2_times else 0,
                          "min": min(phase2_times) if phase2_times else 0,
                          "max": max(phase2_times) if phase2_times else 0},
                "total": {"avg": sum(total_times) / len(total_times) if total_times else 0,
                         "min": min(total_times) if total_times else 0,
                         "max": max(total_times) if total_times else 0}
            }
        }
        result_file = os.path.join(self.perf_dir, "test_result_%drpes.json" % num_rpes)
        with open(result_file, "w") as f:
            json.dump(result, f, indent=2)
        logger.info("=" * 60)
        logger.info("Test Results for %d RPEs:" % num_rpes)
        logger.info("  System Total Time: %.3f seconds" % system_total_time)
        logger.info("  Phase 1 - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase1"]["avg"],
            result["statistics"]["phase1"]["min"],
            result["statistics"]["phase1"]["max"]))
        logger.info("  Phase 2 - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2"]["avg"],
            result["statistics"]["phase2"]["min"],
            result["statistics"]["phase2"]["max"]))
        logger.info("  Total (Individual) - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["total"]["avg"],
            result["statistics"]["total"]["min"],
            result["statistics"]["total"]["max"]))
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        return result

    def run_test_legacy(self, num_rpes):
        """原 run_test：仅等待并收集，不启动 RPO/RPE（兼容 --no-start）"""
        return self.run_test_original_collect_only(num_rpes)

    def run_series(self, start=1, end=None):
        """
        运行一系列测试，从 start 个 RPE 到 end 个 RPE
        """
        if end is None:
            end = self.max_rpe_count
        
        all_results = []
        
        for num_rpes in range(start, end + 1):
            result = self.run_test(num_rpes)
            if result:
                all_results.append(result)
            # 停掉 RPO/RPE 后等待端口释放，再跑下一轮
            if self.stop_after_test and num_rpes < end:
                time.sleep(10)
            else:
                time.sleep(5)
        
        # 生成汇总报告
        self.generate_summary_report(all_results)
        
        return all_results
    
   
    def generate_summary_report(self, all_results):
        """
        生成汇总报告，展示初始化时间随 RPE 数量变化的趋势
        生成 CSV 文件，不包含 system_total_time
        """
        import csv
        
        # 生成 CSV 文件
        csv_file = os.path.join(self.perf_dir, "summary_report.csv")
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # 写入表头
            writer.writerow([
                "Number of RPEs",
                "Phase1 Avg (s)",
                "Phase1 Min (s)",
                "Phase1 Max (s)",
                "Phase2 Avg (s)",
                "Phase2 Min (s)",
                "Phase2 Max (s)",
                "Total Avg (s)",
                "Total Min (s)",
                "Total Max (s)"
            ])
            
            # 写入数据
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                total_stats = result["statistics"]["total"]
                
                writer.writerow([
                    num_rpes,
                    "%.3f" % phase1_stats["avg"],
                    "%.3f" % phase1_stats["min"],
                    "%.3f" % phase1_stats["max"],
                    "%.3f" % phase2_stats["avg"],
                    "%.3f" % phase2_stats["min"],
                    "%.3f" % phase2_stats["max"],
                    "%.3f" % total_stats["avg"],
                    "%.3f" % total_stats["min"],
                    "%.3f" % total_stats["max"]
                ])
        
        # 同时生成文本格式的汇总报告（可选，不包含 system_total_time）
        report_file = os.path.join(self.perf_dir, "summary_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RPE Initialization Performance Test Summary\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Number of RPEs | Phase1 Avg | Phase1 Min | Phase1 Max | "
                   "Phase2 Avg | Phase2 Min | Phase2 Max | "
                   "Total Avg | Total Min | Total Max\n")
            f.write("-" * 120 + "\n")
            
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                total_stats = result["statistics"]["total"]
                
                f.write("%14d | %10.3f | %10.3f | %10.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%9.3f | %9.3f | %9.3f\n" % (
                    num_rpes,
                    phase1_stats["avg"], phase1_stats["min"], phase1_stats["max"],
                    phase2_stats["avg"], phase2_stats["min"], phase2_stats["max"],
                    total_stats["avg"], total_stats["min"], total_stats["max"]
                ))
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Trend Analysis:\n")
            f.write("=" * 80 + "\n")
            
            # 计算趋势（基于 Total Avg）
            if len(all_results) > 1:
                first_avg = all_results[0]["statistics"]["total"]["avg"]
                last_avg = all_results[-1]["statistics"]["total"]["avg"]
                avg_increase = last_avg - first_avg
                rpe_increase = all_results[-1]["num_rpes"] - all_results[0]["num_rpes"]
                
                f.write("Total Avg increase: %.3f seconds (from %d to %d RPEs)\n" % (
                    avg_increase, all_results[0]["num_rpes"], all_results[-1]["num_rpes"]
                ))
                f.write("Average time per additional RPE: %.3f seconds\n" % (
                    avg_increase / rpe_increase if rpe_increase > 0 else 0
                ))
        
        logger.info("Summary report (CSV) saved to: %s" % csv_file)
        logger.info("Summary report (TXT) saved to: %s" % report_file)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RPE Initialization Performance Test (Phase1/Phase2)")
    parser.add_argument("--test", type=str, choices=["phase1", "phase2"], default="phase1",
                        help="phase1: 先 RPO 再 RPE，统计 Phase1 时间；phase2: 先 RPE，等预初始化完成后启 RPO，统计 Phase2 时间")
    parser.add_argument("--max-rpes", type=int, default=5, help="Maximum number of RPEs to test")
    parser.add_argument("--start", type=int, default=1, help="Starting number of RPEs")
    parser.add_argument("--end", type=int, default=None, help="Ending number of RPEs")
    parser.add_argument("--single", type=int, default=None, help="Test with a single number of RPEs")
    parser.add_argument("--perf-dir", type=str, default="./performance_data", help="Performance data directory")
    parser.add_argument("--base-dir", type=str, default=None, help="Project base directory (default: parent of performance/)")
    parser.add_argument("--no-stop", action="store_true", help="Do not stop RPO/RPE after test (leave them running)")
    parser.add_argument("--rpe-dirs", type=str, nargs="+", default=None,
                        help="List of RPE directories (e.g., ../RPE ../RPE1 ../RPE2)")
    
    args = parser.parse_args()
    
    test = RPEPerformanceTest(
        max_rpe_count=args.max_rpes,
        perf_dir=args.perf_dir,
        rpe_dirs=args.rpe_dirs,
        test_mode=args.test,
        base_dir=args.base_dir,
        stop_after_test=not args.no_stop
    )

    def _stop_rpo_rpe_on_signal(signum=None, frame=None):
        """Ctrl+C 或 SIGTERM 时停掉 RPO/RPE，释放端口"""
        logger.info("Received signal %s, stopping RPO and RPE..." % (signum if signum is not None else "?"))
        if test.rpe_starter:
            try:
                test.rpe_starter.stop_all()
            except Exception as e:
                logger.warning("Error stopping RPE: %s" % e)
        if test.rpo_starter:
            try:
                test.rpo_starter.stop_all()
            except Exception as e:
                logger.warning("Error stopping RPO: %s" % e)
        sys.exit(128 + (signum if signum is not None else 0))

    signal.signal(signal.SIGINT, _stop_rpo_rpe_on_signal)
    signal.signal(signal.SIGTERM, _stop_rpo_rpe_on_signal)
    
    if args.single:
        test.run_test(args.single)
    else:
        test.run_series(start=args.start, end=args.end)