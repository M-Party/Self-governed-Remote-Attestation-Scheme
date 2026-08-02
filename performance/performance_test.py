#!/usr/bin/env python3
"""
RPE initialization performance test script.
- Phase1 test: start RPO first, then RPE, and measure Phase1 time versus participant count.
- Phase2 test: start RPE first, wait for all RPEs to finish pre-initialization, signal RPO startup, and measure Phase2 time versus participant count.
- --manual: you start RPEs manually before RPOs; the script waits until all RPEs are ready, signals that RPOs can be started, then waits for Enter and collects results.
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

# Used to import start_multi_rpe / start_multi_rpo inside this script.
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
        self.manual = manual  # True: do not start/stop RPO or RPE; user starts them manually.
        os.makedirs(self.perf_dir, exist_ok=True)
        
        # RPE directory list, for example ["../RPE", "../RPE1", "../RPE2"].
        if rpe_dirs is None:
            self.rpe_dirs = self._discover_rpe_dirs()
        else:
            self.rpe_dirs = rpe_dirs

        self.rpo_starter = None
        self.rpe_starter = None
    
    def _discover_rpe_dirs(self):
        """Automatically discover RPE directories."""
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
        Wait until all RPEs finish pre-initialization, including key generation
        and client initialization, before connecting to RPO. Used by Phase2 tests
        that start RPEs before RPOs.
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

    def wait_for_all_rpes_complete(self, rpe_ids, timeout=600, check_cleared=False):
        """
        Wait until all RPEs complete initialization, meaning Phase 2 is complete.
        If performance files are deleted, search all RPE directories again.
        With check_cleared=True in manual mode, return False immediately when all
        rpe_pre_init_ready_*.flag files have been deleted, enabling retry.
        """
        logger.info("Waiting for all RPEs to complete initialization...")
        start_time = time.time()
        completed_rpes = set()
        # Track discovered performance file paths for each RPE to detect deletion.
        rpe_perf_files = {}
        
        while len(completed_rpes) < len(rpe_ids):
            if time.time() - start_time > timeout:
                logger.error("Timeout waiting for RPEs to complete")
                return False
            # Manual mode: if flags are cleared, treat this round as incomplete and retry.
            if check_cleared and self._is_perf_cleared(rpe_ids):
                logger.info("Pre-initialization flags have been cleared; treating this round as incomplete and retrying.")
                return False

            for rpe_id in rpe_ids:
                # Re-scan all RPE directories for performance files on each loop.
                perf_file = self._find_perf_file(rpe_id)
                
                # If a previously discovered file was deleted, remove it and search again.
                if rpe_id in completed_rpes:
                    if rpe_id in rpe_perf_files:
                        old_file = rpe_perf_files[rpe_id]
                        if not os.path.exists(old_file):
                            logger.warning("Performance file for RPE %s was deleted, re-searching..." % rpe_id)
                            completed_rpes.remove(rpe_id)
                            del rpe_perf_files[rpe_id]
                            # Continue searching for a new file.
                            perf_file = self._find_perf_file(rpe_id)
                    else:
                        # Re-scan when no file path was recorded.
                        perf_file = self._find_perf_file(rpe_id)
                
                # If a performance file is found.
                if perf_file and os.path.exists(perf_file):
                    try:
                        with open(perf_file, 'r') as f:
                            perf_data = json.load(f)
                            if perf_data.get("timestamps", {}).get("init_complete") is not None:
                                # Record the discovered file path.
                                rpe_perf_files[rpe_id] = perf_file
                                if rpe_id not in completed_rpes:
                                    completed_rpes.add(rpe_id)
                                    logger.info("RPE %s completed initialization" % rpe_id)
                    except Exception as e:
                        logger.warning("Error reading perf file for %s: %s" % (rpe_id, e))

            # Manual mode uses a shorter interval to detect cleared flags quickly.
            time.sleep(0.5 if check_cleared else 1)
        
        logger.info("All RPEs completed initialization!")
        return True

    def _find_perf_file(self, rpe_id):
        """Find performance files from all RPE directories."""
        for rpe_dir in self.rpe_dirs:
            perf_file = os.path.join(rpe_dir, "performance_data", f"rpe_perf_{rpe_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None

    def _find_pre_init_flag(self, rpe_id):
        """Find pre-initialization ready flag files from all RPE directories."""
        for rpe_dir in self.rpe_dirs:
            flag_file = os.path.join(rpe_dir, "performance_data", "rpe_pre_init_ready_%s.flag" % rpe_id)
            if os.path.isfile(flag_file):
                return flag_file
        return None

    def _is_perf_cleared(self, rpe_ids):
        """Return whether all rpe_pre_init_ready_*.flag files for each rpe_id are absent."""
        for rpe_id in rpe_ids:
            if self._find_pre_init_flag(rpe_id) is not None:
                return False
        return True
    
    def collect_performance_data(self, rpe_ids):
        """
        Collect performance data from all RPEs.
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
                        
                        # Calculate the system-level time range.
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
        """Clean performance data files under all RPE directories."""
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
        """Phase1 test: start RPO first, then RPE, and measure Phase1 time."""
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
        """Phase2 test: start RPE first, wait for pre-initialization, then start RPO."""
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
        """Collect performance data and generate one test result without start/stop."""
        all_perf_data, earliest_start, latest_end = self.collect_performance_data(rpe_ids)
        if earliest_start and latest_end:
            system_total_time = latest_end - earliest_start
        else:
            system_total_time = None
        phase1_times = []
        phase2_times = []
        phase2_quote_generation_times = []
        phase2_exchange_times = []
        phase2_send_local_quote_times = []
        phase2_wait_remote_quotes_times = []
        phase2_verification_times = []
        phase2_native_quote_verification_times = []
        phase2_policy_enforcement_times = []
        t_exchange_times = []
        t_join_times = []
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
            if durations.get("phase2_send_local_quote") is not None:
                phase2_send_local_quote_times.append(durations["phase2_send_local_quote"])
            if durations.get("phase2_wait_remote_quotes") is not None:
                phase2_wait_remote_quotes_times.append(durations["phase2_wait_remote_quotes"])
            if durations.get("phase2_verification") is not None:
                phase2_verification_times.append(durations["phase2_verification"])
            if durations.get("phase2_native_quote_verification") is not None:
                phase2_native_quote_verification_times.append(durations["phase2_native_quote_verification"])
            if durations.get("phase2_policy_enforcement") is not None:
                phase2_policy_enforcement_times.append(durations["phase2_policy_enforcement"])
            if durations.get("t_exchange") is not None:
                t_exchange_times.append(durations["t_exchange"])
            if durations.get("t_join") is not None:
                t_join_times.append(durations["t_join"])
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
                "phase2_send_local_quote": _build_stats(phase2_send_local_quote_times),
                "phase2_wait_remote_quotes": _build_stats(phase2_wait_remote_quotes_times),
                "phase2_verification": _build_stats(phase2_verification_times),
                "phase2_native_quote_verification": _build_stats(phase2_native_quote_verification_times),
                "phase2_policy_enforcement": _build_stats(phase2_policy_enforcement_times),
                "t_exchange": _build_stats(t_exchange_times),
                "t_join": _build_stats(t_join_times),
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
        logger.info("  Phase 2.2.1 send local quote - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_send_local_quote"]["avg"],
            result["statistics"]["phase2_send_local_quote"]["min"],
            result["statistics"]["phase2_send_local_quote"]["max"]
        ))
        logger.info("  Phase 2.2.2 wait remote quotes - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_wait_remote_quotes"]["avg"],
            result["statistics"]["phase2_wait_remote_quotes"]["min"],
            result["statistics"]["phase2_wait_remote_quotes"]["max"]
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
        logger.info("  Phase 2.4 policy exchange (t_exchange) - Avg: %.6f, Min: %.6f, Max: %.6f" % (
            result["statistics"]["t_exchange"]["avg"],
            result["statistics"]["t_exchange"]["min"],
            result["statistics"]["t_exchange"]["max"]
        ))
        logger.info("  Phase 2.5 consensus join (t_join) - Avg: %.6f, Min: %.6f, Max: %.6f" % (
            result["statistics"]["t_join"]["avg"],
            result["statistics"]["t_join"]["min"],
            result["statistics"]["t_join"]["max"]
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
        Manual mode: do not start or stop RPO/RPE.
        1. Wait for all RPEs to finish pre-initialization, then signal RPO startup.
        2. Wait for all RPEs to complete initialization, then collect data.
        On failure, the user exits all RPEs; the script retries after detecting cleanup.
        """
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        while True:
            self._cleanup_perf_files()
            logger.info("=" * 60)
            logger.info("Manual mode: %d RPE(s). Please start all RPEs first (do not start RPO yet)." % num_rpes)
            logger.info("base_dir=%s, rpe_dirs=%s (must match the project root used by start_multi_rpe)" % (self.base_dir, self.rpe_dirs))
            logger.info("=" * 60)
            if not self.wait_for_all_rpes_pre_init_ready(rpe_ids):
                logger.error("Manual test failed: not all RPEs became pre-init ready")
                return None
            # ---------- Signal: all RPEs are pre-initialized; start RPO now. ----------
            _signal_msg = ">>> Signal: all RPEs are pre-initialized; start RPO now <<<"
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
                input("Press Enter after starting RPO... ")
            except EOFError:
                logger.info("(no stdin, waiting 10s for you to start RPO...)")
                time.sleep(10)
            logger.info("Waiting for all RPEs to complete full initialization...")
            success = self.wait_for_all_rpes_complete(rpe_ids, check_cleared=True)
            if success:
                return self._collect_and_report(num_rpes, rpe_ids)
            # Not all RPEs completed; user handles failure and exits RPEs, script only detects flag cleanup.
            logger.warning("Not all RPEs completed initialization. After exiting all RPEs, delete rpe_pre_init_ready_*.flag under each RPE performance_data directory. You can run: python start_multi_rpe.py --num-parties %d --delete-flags-only" % num_rpes)
            logger.info("After those flags are deleted, the script will wait for RPE pre-initialization again and continue this round...")
            while not self._is_perf_cleared(rpe_ids):
                time.sleep(2)
            logger.info("Detected cleanup; restarting the current round.")

    def run_test(self, num_rpes):
        """
        Run a performance test with the specified number of RPEs.
        Phase1: start RPO before RPE and measure Phase1 time.
        Phase2: start RPE first, then start RPO after pre-initialization.
        --manual: user starts RPE/RPO manually; the script signals when RPO can start.
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
        """Only wait for existing RPEs to complete initialization and collect data."""
        rpe_ids = [f"rpe-{i+1}" for i in range(num_rpes)]
        self._cleanup_perf_files()
        success = self.wait_for_all_rpes_complete(rpe_ids)
        if not success:
            logger.error("Test failed: not all RPEs completed initialization")
            return None
        return self._collect_and_report(num_rpes, rpe_ids)

    def run_test_original_collect_only(self, num_rpes):
        """
        Legacy logic: do not start RPO/RPE; only wait for all RPEs to complete
        initialization and collect data. Kept for manual RPO/RPE startup scenarios.
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
        phase2_send_local_quote_times = []
        phase2_wait_remote_quotes_times = []
        phase2_verification_times = []
        phase2_native_quote_verification_times = []
        phase2_policy_enforcement_times = []
        t_exchange_times = []
        t_join_times = []
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
            if durations.get("phase2_send_local_quote") is not None:
                phase2_send_local_quote_times.append(durations["phase2_send_local_quote"])
            if durations.get("phase2_wait_remote_quotes") is not None:
                phase2_wait_remote_quotes_times.append(durations["phase2_wait_remote_quotes"])
            if durations.get("phase2_verification") is not None:
                phase2_verification_times.append(durations["phase2_verification"])
            if durations.get("phase2_native_quote_verification") is not None:
                phase2_native_quote_verification_times.append(durations["phase2_native_quote_verification"])
            if durations.get("phase2_policy_enforcement") is not None:
                phase2_policy_enforcement_times.append(durations["phase2_policy_enforcement"])
            if durations.get("t_exchange") is not None:
                t_exchange_times.append(durations["t_exchange"])
            if durations.get("t_join") is not None:
                t_join_times.append(durations["t_join"])
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
                "phase2_send_local_quote": _build_stats(phase2_send_local_quote_times),
                "phase2_wait_remote_quotes": _build_stats(phase2_wait_remote_quotes_times),
                "phase2_verification": _build_stats(phase2_verification_times),
                "phase2_native_quote_verification": _build_stats(phase2_native_quote_verification_times),
                "phase2_policy_enforcement": _build_stats(phase2_policy_enforcement_times),
                "t_exchange": _build_stats(t_exchange_times),
                "t_join": _build_stats(t_join_times),
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
        logger.info("  Phase 2.2.1 send local quote - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_send_local_quote"]["avg"],
            result["statistics"]["phase2_send_local_quote"]["min"],
            result["statistics"]["phase2_send_local_quote"]["max"]))
        logger.info("  Phase 2.2.2 wait remote quotes - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["phase2_wait_remote_quotes"]["avg"],
            result["statistics"]["phase2_wait_remote_quotes"]["min"],
            result["statistics"]["phase2_wait_remote_quotes"]["max"]))
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
        logger.info("  Phase 2.4 policy exchange (t_exchange) - Avg: %.6f, Min: %.6f, Max: %.6f" % (
            result["statistics"]["t_exchange"]["avg"],
            result["statistics"]["t_exchange"]["min"],
            result["statistics"]["t_exchange"]["max"]
        ))
        logger.info("  Phase 2.5 consensus join (t_join) - Avg: %.6f, Min: %.6f, Max: %.6f" % (
            result["statistics"]["t_join"]["avg"],
            result["statistics"]["t_join"]["min"],
            result["statistics"]["t_join"]["max"]
        ))
        logger.info("  Total (Individual) - Avg: %.3f, Min: %.3f, Max: %.3f" % (
            result["statistics"]["total"]["avg"],
            result["statistics"]["total"]["min"],
            result["statistics"]["total"]["max"]))
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        return result

    def run_test_legacy(self, num_rpes):
        """Legacy run_test: only wait and collect, without starting RPO/RPE."""
        return self.run_test_original_collect_only(num_rpes)

    def run_series(self, start=1, end=None):
        """
        Run a series of tests from start to end RPE counts.
        """
        if end is None:
            end = self.max_rpe_count
        
        all_results = []
        
        for num_rpes in range(start, end + 1):
            result = self.run_test(num_rpes)
            if result:
                all_results.append(result)
            # Wait for ports to be released after stopping RPO/RPE before the next round.
            if self.stop_after_test and num_rpes < end:
                time.sleep(10)
            else:
                time.sleep(5)
        
        # Generate the summary report.
        self.generate_summary_report(all_results)
        
        return all_results
    
   
    def generate_summary_report(self, all_results, name_suffix=None):
        """
        Generate a summary report showing initialization time trends by RPE count.
        Generate a CSV file that excludes system_total_time.
        """
        import csv

        suffix = ""
        if name_suffix:
            suffix = "_%s" % name_suffix
        
        # Generate the CSV file.
        csv_file = os.path.join(self.perf_dir, "summary_report%s.csv" % suffix)
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write the header.
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
                "Phase2.2.1 Send Local Quote Avg (s)",
                "Phase2.2.1 Send Local Quote Min (s)",
                "Phase2.2.1 Send Local Quote Max (s)",
                "Phase2.2.2 Wait Remote Quotes Avg (s)",
                "Phase2.2.2 Wait Remote Quotes Min (s)",
                "Phase2.2.2 Wait Remote Quotes Max (s)",
                "Phase2.3 Quote Verification Avg (s)",
                "Phase2.3 Quote Verification Min (s)",
                "Phase2.3 Quote Verification Max (s)",
                "Phase2.3.1 Native Quote Verification Avg (s)",
                "Phase2.3.1 Native Quote Verification Min (s)",
                "Phase2.3.1 Native Quote Verification Max (s)",
                "Phase2.3.2 Policy Enforcement Avg (s)",
                "Phase2.3.2 Policy Enforcement Min (s)",
                "Phase2.3.2 Policy Enforcement Max (s)",
                "t_exchange Avg (s)",
                "t_exchange Min (s)",
                "t_exchange Max (s)",
                "t_join Avg (s)",
                "t_join Min (s)",
                "t_join Max (s)",
                "Total Avg (s)",
                "Total Min (s)",
                "Total Max (s)"
            ])
            
            # Write data rows.
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                phase2_quote_generation_stats = result["statistics"]["phase2_quote_generation"]
                phase2_exchange_stats = result["statistics"]["phase2_exchange"]
                phase2_send_local_quote_stats = result["statistics"].get("phase2_send_local_quote") or {"avg": 0, "min": 0, "max": 0}
                phase2_wait_remote_quotes_stats = result["statistics"].get("phase2_wait_remote_quotes") or {"avg": 0, "min": 0, "max": 0}
                phase2_verification_stats = result["statistics"]["phase2_verification"]
                phase2_native_quote_verification_stats = result["statistics"]["phase2_native_quote_verification"]
                phase2_policy_enforcement_stats = result["statistics"]["phase2_policy_enforcement"]
                t_exchange_stats = result["statistics"].get("t_exchange") or {"avg": 0, "min": 0, "max": 0}
                t_join_stats = result["statistics"].get("t_join") or {"avg": 0, "min": 0, "max": 0}
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
                    "%.3f" % phase2_send_local_quote_stats["avg"],
                    "%.3f" % phase2_send_local_quote_stats["min"],
                    "%.3f" % phase2_send_local_quote_stats["max"],
                    "%.3f" % phase2_wait_remote_quotes_stats["avg"],
                    "%.3f" % phase2_wait_remote_quotes_stats["min"],
                    "%.3f" % phase2_wait_remote_quotes_stats["max"],
                    "%.3f" % phase2_verification_stats["avg"],
                    "%.3f" % phase2_verification_stats["min"],
                    "%.3f" % phase2_verification_stats["max"],
                    "%.3f" % phase2_native_quote_verification_stats["avg"],
                    "%.3f" % phase2_native_quote_verification_stats["min"],
                    "%.3f" % phase2_native_quote_verification_stats["max"],
                    "%.3f" % phase2_policy_enforcement_stats["avg"],
                    "%.3f" % phase2_policy_enforcement_stats["min"],
                    "%.3f" % phase2_policy_enforcement_stats["max"],
                    "%.6f" % t_exchange_stats["avg"],
                    "%.6f" % t_exchange_stats["min"],
                    "%.6f" % t_exchange_stats["max"],
                    "%.6f" % t_join_stats["avg"],
                    "%.6f" % t_join_stats["min"],
                    "%.6f" % t_join_stats["max"],
                    "%.3f" % total_stats["avg"],
                    "%.3f" % total_stats["min"],
                    "%.3f" % total_stats["max"]
                ])
        
        # Also generate a text summary report, excluding system_total_time.
        report_file = os.path.join(self.perf_dir, "summary_report%s.txt" % suffix)
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RPE Initialization Performance Test Summary\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Number of RPEs | Phase1 Avg | Phase1 Min | Phase1 Max | "
                   "Phase2 Avg | Phase2 Min | Phase2 Max | "
                   "P2.1 Avg | P2.1 Min | P2.1 Max | "
                   "P2.2 Avg | P2.2 Min | P2.2 Max | "
                   "P2.2.1 Avg | P2.2.1 Min | P2.2.1 Max | "
                   "P2.2.2 Avg | P2.2.2 Min | P2.2.2 Max | "
                   "P2.3 Avg | P2.3 Min | P2.3 Max | "
                   "P2.3.1 Avg | P2.3.1 Min | P2.3.1 Max | "
                   "P2.3.2 Avg | P2.3.2 Min | P2.3.2 Max | "
                   "Total Avg | Total Min | Total Max\n")
            f.write("-" * 360 + "\n")
            
            for result in all_results:
                num_rpes = result["num_rpes"]
                phase1_stats = result["statistics"]["phase1"]
                phase2_stats = result["statistics"]["phase2"]
                phase2_quote_generation_stats = result["statistics"]["phase2_quote_generation"]
                phase2_exchange_stats = result["statistics"]["phase2_exchange"]
                phase2_send_local_quote_stats = result["statistics"].get("phase2_send_local_quote") or {"avg": 0, "min": 0, "max": 0}
                phase2_wait_remote_quotes_stats = result["statistics"].get("phase2_wait_remote_quotes") or {"avg": 0, "min": 0, "max": 0}
                phase2_verification_stats = result["statistics"]["phase2_verification"]
                phase2_native_quote_verification_stats = result["statistics"]["phase2_native_quote_verification"]
                phase2_policy_enforcement_stats = result["statistics"]["phase2_policy_enforcement"]
                total_stats = result["statistics"]["total"]
                
                f.write("%14d | %10.3f | %10.3f | %10.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%9.3f | %9.3f | %9.3f | "
                       "%9.3f | %9.3f | %9.3f | "
                       "%8.3f | %8.3f | %8.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%10.3f | %10.3f | %10.3f | "
                       "%9.3f | %9.3f | %9.3f\n" % (
                    num_rpes,
                    phase1_stats["avg"], phase1_stats["min"], phase1_stats["max"],
                    phase2_stats["avg"], phase2_stats["min"], phase2_stats["max"],
                    phase2_quote_generation_stats["avg"], phase2_quote_generation_stats["min"], phase2_quote_generation_stats["max"],
                    phase2_exchange_stats["avg"], phase2_exchange_stats["min"], phase2_exchange_stats["max"],
                    phase2_send_local_quote_stats["avg"], phase2_send_local_quote_stats["min"], phase2_send_local_quote_stats["max"],
                    phase2_wait_remote_quotes_stats["avg"], phase2_wait_remote_quotes_stats["min"], phase2_wait_remote_quotes_stats["max"],
                    phase2_verification_stats["avg"], phase2_verification_stats["min"], phase2_verification_stats["max"],
                    phase2_native_quote_verification_stats["avg"], phase2_native_quote_verification_stats["min"], phase2_native_quote_verification_stats["max"],
                    phase2_policy_enforcement_stats["avg"], phase2_policy_enforcement_stats["min"], phase2_policy_enforcement_stats["max"],
                    total_stats["avg"], total_stats["min"], total_stats["max"]
                ))
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Trend Analysis:\n")
            f.write("=" * 80 + "\n")
            
            # Calculate trends based on Total Avg.
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
        """Read existing test_result_*rpes.json files and generate a suffixed summary report."""
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
                        help="phase1: start RPO before RPE and measure Phase1 time; phase2: start RPE first, then start RPO after pre-initialization")
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
        """Stop RPO/RPE and release ports on Ctrl+C or SIGTERM; do not kill processes in manual mode."""
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
