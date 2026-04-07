#!/usr/bin/env python3
"""
RPE 初始化性能测试脚本
- Phase1 测试：先启动 RPO 再启动 RPE，统计 Phase1 时间随参与方数量变化
- Phase2 测试：先启动 RPE，等所有 RPE 预初始化完成后给出信号再启动 RPO，统计 Phase2 时间随参与方数量变化
- --manual：由你手动启动 RPE（先不启 RPO）；脚本等所有 RPE 预初始化就绪后给出「请现在启动 RPO」信号，你启动 RPO 后按 Enter，脚本再等待完成并收集结果
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


def _build_stats(values):
    return {
        "avg": sum(values) / len(values) if values else 0,
        "min": min(values) if values else 0,
        "max": max(values) if values else 0,
    }


class RPEPerformanceTest:
    def __init__(self, max_rpe_count=5, perf_dir="./performance_data", rpe_dirs=None,
                 test_mode="phase1", base_dir=None, stop_after_test=True, manual=False):
        self.max_rpe_count = max_rpe_count
        self.perf_dir = perf_dir
        self.test_mode = test_mode  # "phase1" or "phase2"
        self.base_dir = base_dir or os.path.dirname(_script_dir)
        self.stop_after_test = stop_after_test
        self.manual = manual  # True: 不启动/不停止 RPO、RPE，由用户手动启动；会给出「可启动 RPO」信号
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

    def wait_for_all_rpes_complete(self, rpe_ids, timeout=300, check_cleared=False):
        """
        等待所有 RPE 完成初始化（Phase 2 完成）
        如果性能文件被删除，会重新从所有 RPE 目录查找
        check_cleared=True（manual 模式）：若检测到 rpe_pre_init_ready_*.flag 已全部删除，立即视为未完成并返回 False，便于重试流程
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
            # manual 模式：一旦检测到 flag 已清空（你已退出 RPE 并删 flag），立即视为未完成并重试
            if check_cleared and self._is_perf_cleared(rpe_ids):
                logger.info("检测到预初始化 flag 已清空，视为本轮未完成，重新开始当前轮次。")
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

            # manual 模式用较短间隔以便尽快检测到 flag 清空并重试
            time.sleep(0.5 if check_cleared else 1)
        
        logger.info("All RPEs completed initialization!")
        return True

    def _find_perf_file(self, rpe_id):
        """从所有 RPE 目录中查找性能文件"""
        for rpe_dir in self.rpe_dirs:
            perf_file = os.path.join(rpe_dir, "performance_data", f"rpe_perf_{rpe_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None

    def _find_pre_init_flag(self, rpe_id):
        """从所有 RPE 目录中查找预初始化就绪 flag 文件"""
        for rpe_dir in self.rpe_dirs:
            flag_file = os.path.join(rpe_dir, "performance_data", "rpe_pre_init_ready_%s.flag" % rpe_id)
            if os.path.isfile(flag_file):
                return flag_file
        return None

    def _is_perf_cleared(self, rpe_ids):
        """判断是否已清空：各 rpe_id 的 rpe_pre_init_ready_*.flag 均不存在（Phase2 失败时 rpe_perf_*.json 可能不生成；已完成的会写 rpe_perf_*.json，故只以 flag 为准）"""
        for rpe_id in rpe_ids:
            if self._find_pre_init_flag(rpe_id) is not None:
                return False
        return True
    
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
        phase2_quote_generation_times = []
        phase2_exchange_times = []
        phase2_verification_times = []
        phase2_native_quote_verification_times = []
        phase2_policy_enforcement_times = []
        total_times = []
        for rpe_id, perf_data in all_perf_data.items():
            durations = perf_data.get("durations", {})
            if durations.get("phase1"):
                phase1_times.append(durations["phase1"])
            if durations.get("phase2"):
                phase2_times.append(durations["phase2"])
            if durations.get("phase2_quote_generation") is not None:
                phase2_quote_generation_times.append(durations["phase2_quote_generation"])
            if durations.get("phase2_exchange") is not None:
                phase2_exchange_times.append(durations["phase2_exchange"])
            if durations.get("phase2_verification") is not None:
                phase2_verification_times.append(durations["phase2_verification"])
            if durations.get("phase2_native_quote_verification") is not None:
                phase2_native_quote_verification_times.append(durations["phase2_native_quote_verification"])
            if durations.get("phase2_policy_enforcement") is not None:
                phase2_policy_enforcement_times.append(durations["phase2_policy_enforcement"])
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
                "phase1": _build_stats(phase1_times),
                "phase2": _build_stats(phase2_times),
                "phase2_quote_generation": _build_stats(phase2_quote_generation_times),
                "phase2_exchange": _build_stats(phase2_exchange_times),
                "phase2_verification": _build_stats(phase2_verification_times),
                "phase2_native_quote_verification": _build_stats(phase2_native_quote_verification_times),
                "phase2_policy_enforcement": _build_stats(phase2_policy_enforcement_times),
                "total": _build_stats(total_times),
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
        logger.info("  Phase 2.1 local quote generation - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_quote_generation"]["avg"],
            result["statistics"]["phase2_quote_generation"]["min"],
            result["statistics"]["phase2_quote_generation"]["max"]
        ))
        logger.info("  Phase 2.2 quote exchange - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_exchange"]["avg"],
            result["statistics"]["phase2_exchange"]["min"],
            result["statistics"]["phase2_exchange"]["max"]
        ))
        logger.info("  Phase 2.3 quote verification - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_verification"]["avg"],
            result["statistics"]["phase2_verification"]["min"],
            result["statistics"]["phase2_verification"]["max"]
        ))
        logger.info("  Phase 2.3.1 native quote verification - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_native_quote_verification"]["avg"],
            result["statistics"]["phase2_native_quote_verification"]["min"],
            result["statistics"]["phase2_native_quote_verification"]["max"]
        ))
        logger.info("  Phase 2.3.2 policy enforcement - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_policy_enforcement"]["avg"],
            result["statistics"]["phase2_policy_enforcement"]["min"],
            result["statistics"]["phase2_policy_enforcement"]["max"]
        ))
        logger.info("  Total (Individual) - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["total"]["avg"],
            result["statistics"]["total"]["min"],
            result["statistics"]["total"]["max"]
        ))
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        return result

    def _run_test_manual(self, num_rpes):
        """
        手动模式：不启动/不停止 RPO 和 RPE。
        1) 先等所有 RPE 预初始化就绪 → 给出「请现在启动 RPO」信号
        2) 再等所有 RPE 完全初始化完成 → 收集数据
        失败时由你自行判断并退出所有 RPE；脚本通过检测 performance_data 是否清空来自动重试当前轮次。
        """
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        while True:
            self._cleanup_perf_files()
            logger.info("=" * 60)
            logger.info("Manual mode: %d RPE(s). Please start all RPEs first (do not start RPO yet)." % num_rpes)
            logger.info("base_dir=%s, rpe_dirs=%s（与 start_multi_rpe 须同一项目根）" % (self.base_dir, self.rpe_dirs))
            logger.info("=" * 60)
            if not self.wait_for_all_rpes_pre_init_ready(rpe_ids):
                logger.error("Manual test failed: not all RPEs became pre-init ready")
                return None
            # ---------- 信号：所有 RPE 已预初始化就绪，请现在启动 RPO ----------
            _signal_msg = ">>> 信号：所有 RPE 已预初始化就绪，请现在启动 RPO <<<"
            for _ in range(3):
                logger.info("")
            logger.info("=" * 60)
            logger.info(_signal_msg)
            logger.info("=" * 60)
            for _ in range(3):
                logger.info("")
            try:
                with open(os.path.join(self.perf_dir, "START_RPO_NOW.flag"), "w") as f:
                    f.write(_signal_msg + "\n")
            except Exception:
                pass
            try:
                input("启动 RPO 后按 Enter 继续... ")
            except EOFError:
                logger.info("(no stdin, waiting 10s for you to start RPO...)")
                time.sleep(10)
            logger.info("Waiting for all RPEs to complete full initialization...")
            success = self.wait_for_all_rpes_complete(rpe_ids, check_cleared=True)
            if success:
                return self._collect_and_report(num_rpes, rpe_ids)
            # 未全部完成：由你判断失败并退出所有 RPE，脚本只检测 flag 是否清空
            logger.warning("未全部完成初始化。若已退出所有 RPE，请删除各 RPE 目录下 performance_data 中的 rpe_pre_init_ready_*.flag（可运行: python start_multi_rpe.py --num-parties %d --delete-flags-only）" % num_rpes)
            logger.info("检测到上述 flag 已删除后，将自动重新等待 RPE 预初始化就绪并继续当前轮次...")
            while not self._is_perf_cleared(rpe_ids):
                time.sleep(2)
            logger.info("已检测到文件清空，重新开始当前轮次。")

    def run_test(self, num_rpes):
        """
        运行指定数量 RPE 的性能测试
        Phase1：先 RPO 再 RPE，统计 Phase1 时间
        Phase2：先 RPE，等预初始化完成后启 RPO，统计 Phase2 时间
        --manual：手动启 RPE/RPO，脚本给出「可启动 RPO」信号后等待完成并收集
        """
        logger.info("=" * 60)
        logger.info("Starting %s performance test with %d RPEs" % (self.test_mode, num_rpes))
        logger.info("=" * 60)
        if self.manual:
            return self._run_test_manual(num_rpes)
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
        phase2_quote_generation_times = []
        phase2_exchange_times = []
        phase2_verification_times = []
        phase2_native_quote_verification_times = []
        phase2_policy_enforcement_times = []
        total_times = []
        for rpe_id, perf_data in all_perf_data.items():
            durations = perf_data.get("durations", {})
            if durations.get("phase1"):
                phase1_times.append(durations["phase1"])
            if durations.get("phase2"):
                phase2_times.append(durations["phase2"])
            if durations.get("phase2_quote_generation") is not None:
                phase2_quote_generation_times.append(durations["phase2_quote_generation"])
            if durations.get("phase2_exchange") is not None:
                phase2_exchange_times.append(durations["phase2_exchange"])
            if durations.get("phase2_verification") is not None:
                phase2_verification_times.append(durations["phase2_verification"])
            if durations.get("phase2_native_quote_verification") is not None:
                phase2_native_quote_verification_times.append(durations["phase2_native_quote_verification"])
            if durations.get("phase2_policy_enforcement") is not None:
                phase2_policy_enforcement_times.append(durations["phase2_policy_enforcement"])
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
                "phase1": _build_stats(phase1_times),
                "phase2": _build_stats(phase2_times),
                "phase2_quote_generation": _build_stats(phase2_quote_generation_times),
                "phase2_exchange": _build_stats(phase2_exchange_times),
                "phase2_verification": _build_stats(phase2_verification_times),
                "phase2_native_quote_verification": _build_stats(phase2_native_quote_verification_times),
                "phase2_policy_enforcement": _build_stats(phase2_policy_enforcement_times),
                "total": _build_stats(total_times),
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
        logger.info("  Phase 2.1 local quote generation - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_quote_generation"]["avg"],
            result["statistics"]["phase2_quote_generation"]["min"],
            result["statistics"]["phase2_quote_generation"]["max"]))
        logger.info("  Phase 2.2 quote exchange - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_exchange"]["avg"],
            result["statistics"]["phase2_exchange"]["min"],
            result["statistics"]["phase2_exchange"]["max"]))
        logger.info("  Phase 2.3 quote verification - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_verification"]["avg"],
            result["statistics"]["phase2_verification"]["min"],
            result["statistics"]["phase2_verification"]["max"]))
        logger.info("  Phase 2.3.1 native quote verification - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_native_quote_verification"]["avg"],
            result["statistics"]["phase2_native_quote_verification"]["min"],
            result["statistics"]["phase2_native_quote_verification"]["max"]))
        logger.info("  Phase 2.3.2 policy enforcement - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_policy_enforcement"]["avg"],
            result["statistics"]["phase2_policy_enforcement"]["min"],
            result["statistics"]["phase2_policy_enforcement"]["max"]))
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
    
   
    def generate_summary_report(self, all_results, name_suffix=None):
        """
        生成汇总报告，展示初始化时间随 RPE 数量变化的趋势
        生成 CSV 文件，不包含 system_total_time
        """
        import csv

        suffix = ""
        if name_suffix:
            suffix = "_%s" % name_suffix
        
        # 生成 CSV 文件
        csv_file = os.path.join(self.perf_dir, "summary_report%s.csv" % suffix)
        
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
                "Phase2.1 Quote Generation Avg (s)",
                "Phase2.1 Quote Generation Min (s)",
                "Phase2.1 Quote Generation Max (s)",
                "Phase2.2 Quote Exchange Avg (s)",
                "Phase2.2 Quote Exchange Min (s)",
                "Phase2.2 Quote Exchange Max (s)",
                "Phase2.3 Quote Verification Avg (s)",
                "Phase2.3 Quote Verification Min (s)",
                "Phase2.3 Quote Verification Max (s)",
                "Phase2.3.1 Native Quote Verification Avg (s)",
                "Phase2.3.1 Native Quote Verification Min (s)",
                "Phase2.3.1 Native Quote Verification Max (s)",
                "Phase2.3.2 Policy Enforcement Avg (s)",
                "Phase2.3.2 Policy Enforcement Min (s)",
                "Phase2.3.2 Policy Enforcement Max (s)",
                "Total Avg (s)",
                "Total Min (s)",
                "Total Max (s)"
            ])
            
            # 写入数据
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                phase2_quote_generation_stats = result["statistics"]["phase2_quote_generation"]
                phase2_exchange_stats = result["statistics"]["phase2_exchange"]
                phase2_verification_stats = result["statistics"]["phase2_verification"]
                phase2_native_quote_verification_stats = result["statistics"]["phase2_native_quote_verification"]
                phase2_policy_enforcement_stats = result["statistics"]["phase2_policy_enforcement"]
                total_stats = result["statistics"]["total"]
                
                writer.writerow([
                    num_rpes,
                    "%.3f" % phase1_stats["avg"],
                    "%.3f" % phase1_stats["min"],
                    "%.3f" % phase1_stats["max"],
                    "%.3f" % phase2_stats["avg"],
                    "%.3f" % phase2_stats["min"],
                    "%.3f" % phase2_stats["max"],
                    "%.3f" % phase2_quote_generation_stats["avg"],
                    "%.3f" % phase2_quote_generation_stats["min"],
                    "%.3f" % phase2_quote_generation_stats["max"],
                    "%.3f" % phase2_exchange_stats["avg"],
                    "%.3f" % phase2_exchange_stats["min"],
                    "%.3f" % phase2_exchange_stats["max"],
                    "%.3f" % phase2_verification_stats["avg"],
                    "%.3f" % phase2_verification_stats["min"],
                    "%.3f" % phase2_verification_stats["max"],
                    "%.3f" % phase2_native_quote_verification_stats["avg"],
                    "%.3f" % phase2_native_quote_verification_stats["min"],
                    "%.3f" % phase2_native_quote_verification_stats["max"],
                    "%.3f" % phase2_policy_enforcement_stats["avg"],
                    "%.3f" % phase2_policy_enforcement_stats["min"],
                    "%.3f" % phase2_policy_enforcement_stats["max"],
                    "%.3f" % total_stats["avg"],
                    "%.3f" % total_stats["min"],
                    "%.3f" % total_stats["max"]
                ])
        
        # 同时生成文本格式的汇总报告（可选，不包含 system_total_time）
        report_file = os.path.join(self.perf_dir, "summary_report%s.txt" % suffix)
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RPE Initialization Performance Test Summary\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Number of RPEs | Phase1 Avg | Phase1 Min | Phase1 Max | "
                   "Phase2 Avg | Phase2 Min | Phase2 Max | "
                   "P2.1 Avg | P2.1 Min | P2.1 Max | "
                   "P2.2 Avg | P2.2 Min | P2.2 Max | "
                   "P2.3 Avg | P2.3 Min | P2.3 Max | "
                   "P2.3.1 Avg | P2.3.1 Min | P2.3.1 Max | "
                   "P2.3.2 Avg | P2.3.2 Min | P2.3.2 Max | "
                   "Total Avg | Total Min | Total Max\n")
            f.write("-" * 300 + "\n")
            
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                phase2_quote_generation_stats = result["statistics"]["phase2_quote_generation"]
                phase2_exchange_stats = result["statistics"]["phase2_exchange"]
                phase2_verification_stats = result["statistics"]["phase2_verification"]
                phase2_native_quote_verification_stats = result["statistics"]["phase2_native_quote_verification"]
                phase2_policy_enforcement_stats = result["statistics"]["phase2_policy_enforcement"]
                total_stats = result["statistics"]["total"]
                
                f.write("%14d | %10.3f | %10.3f | %10.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%9.3f | %9.3f | %9.3f\n" % (
                    num_rpes,
                    phase1_stats["avg"], phase1_stats["min"], phase1_stats["max"],
                    phase2_stats["avg"], phase2_stats["min"], phase2_stats["max"],
                    phase2_quote_generation_stats["avg"], phase2_quote_generation_stats["min"], phase2_quote_generation_stats["max"],
                    phase2_exchange_stats["avg"], phase2_exchange_stats["min"], phase2_exchange_stats["max"],
                    phase2_verification_stats["avg"], phase2_verification_stats["min"], phase2_verification_stats["max"],
                    phase2_native_quote_verification_stats["avg"], phase2_native_quote_verification_stats["min"], phase2_native_quote_verification_stats["max"],
                    phase2_policy_enforcement_stats["avg"], phase2_policy_enforcement_stats["min"], phase2_policy_enforcement_stats["max"],
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

    def generate_summary_report_from_existing(self, rpe_counts):
        """从现有 test_result_*rpes.json 读取结果并生成带参与方后缀的汇总报告"""
        all_results = []
        missing_counts = []

        for num_rpes in rpe_counts:
            result_file = os.path.join(self.perf_dir, "test_result_%drpes.json" % num_rpes)
            if not os.path.exists(result_file):
                missing_counts.append(num_rpes)
                continue
            try:
                with open(result_file, "r") as f:
                    all_results.append(json.load(f))
            except Exception as e:
                logger.warning("Failed to read existing result file %s: %s" % (result_file, e))

        if missing_counts:
            logger.warning("Missing test result files for RPE counts: %s" % ", ".join(str(count) for count in missing_counts))

        if not all_results:
            logger.error("No existing test results found under %s" % self.perf_dir)
            return None

        all_results.sort(key=lambda result: result.get("num_rpes", 0))
        name_suffix = "_".join(str(result["num_rpes"]) for result in all_results)
        self.generate_summary_report(all_results, name_suffix=name_suffix)
        return all_results


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
    parser.add_argument("--manual", action="store_true",
                        help="Manual start: you start RPE then RPO; script waits for pre-init ready, prints signal to start RPO, then waits for completion and collects results")
    parser.add_argument("--rpe-dirs", type=str, nargs="+", default=None,
                        help="List of RPE directories (e.g., ../RPE ../RPE1 ../RPE2)")
    parser.add_argument("--report-from", type=int, nargs="+", default=None,
                        help="Generate summary report from existing test_result_*rpes.json files, e.g. --report-from 2 4 8")
    
    args = parser.parse_args()
    
    test = RPEPerformanceTest(
        max_rpe_count=args.max_rpes,
        perf_dir=args.perf_dir,
        rpe_dirs=args.rpe_dirs,
        test_mode=args.test,
        base_dir=args.base_dir,
        stop_after_test=not args.no_stop,
        manual=getattr(args, "manual", False)
    )

    def _stop_rpo_rpe_on_signal(signum=None, frame=None):
        """Ctrl+C 或 SIGTERM 时停掉 RPO/RPE，释放端口（manual 模式下不杀进程）"""
        if test.manual:
            logger.info("Received signal %s (manual mode: not stopping RPO/RPE)" % (signum if signum is not None else "?"))
            sys.exit(128 + (signum if signum is not None else 0))
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
    
    if args.report_from:
        test.generate_summary_report_from_existing(args.report_from)
    elif args.single:
        test.run_test(args.single)
    else:
        test.run_series(start=args.start, end=args.end)
