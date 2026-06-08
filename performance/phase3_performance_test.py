#!/usr/bin/env python3
"""
Phase 3 performance test script.
Measures how RPE-to-CE authentication latency and throughput vary with CE count.
"""
import json
import time
import os
import sys
import subprocess
import glob
import logging
import csv
import re
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Phase3PerformanceTest:
    def __init__(self, perf_dir="./performance_data", rpe_dir=None, ce_base_dir=None):
        self.perf_dir = perf_dir
        os.makedirs(self.perf_dir, exist_ok=True)
        
        # Base RPE directory used to discover all RPEs automatically.
        if rpe_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rpe_base_dir = base_dir
            self.rpe_dir = None
        else:
            # If a single RPE directory is specified, use only that directory.
            # Convert relative paths to absolute paths.
            if not os.path.isabs(rpe_dir):
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self.rpe_dir = os.path.join(base_dir, rpe_dir.rstrip('/'))
            else:
                self.rpe_dir = rpe_dir.rstrip('/')
            # If the specified directory exists, use its parent as base_dir to find other RPEs.
            if os.path.isdir(self.rpe_dir):
                self.rpe_base_dir = os.path.dirname(self.rpe_dir)
            else:
                self.rpe_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        # Base CE directory.
        if ce_base_dir is None:
            self.ce_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            self.ce_base_dir = ce_base_dir
    
    def _discover_ce_dirs(self):
        """Automatically discover CE directories and sort them by CE_party number."""
        ce_dirs = []
        for path in glob.glob(os.path.join(self.ce_base_dir, "CE_party*")):
            if os.path.isdir(path):
                ce_dirs.append(path)
        def _party_num(p):
            name = os.path.basename(p.rstrip(os.sep))
            if name.startswith("CE_party"):
                try:
                    return int(name[8:])
                except ValueError:
                    return 0
            return 0
        return sorted(ce_dirs, key=_party_num)
    
    def _discover_rpe_dirs(self):
        """Automatically discover all RPE directories."""
        # If rpe_dir is specified, use it directly.
        if hasattr(self, 'rpe_dir') and self.rpe_dir:
            if os.path.isdir(self.rpe_dir):
                logger.debug("Using specified RPE directory: %s" % self.rpe_dir)
                return [self.rpe_dir]
            else:
                logger.warning("Specified RPE directory does not exist: %s" % self.rpe_dir)
        
        # Otherwise discover all RPE directories automatically.
        rpe_dirs = []
        # First look for RPE_party* directories.
        for path in glob.glob(os.path.join(self.rpe_base_dir, "RPE_party*")):
            if os.path.isdir(path):
                rpe_dirs.append(path)
        # Also look for a single RPE directory, where files may be located.
        rpe_dir = os.path.join(self.rpe_base_dir, "RPE")
        if os.path.isdir(rpe_dir):
            rpe_dirs.append(rpe_dir)
        logger.debug("Auto-discovered RPE directories: %s" % rpe_dirs)
        return sorted(rpe_dirs)
    
    def _find_rpe_perf_file(self, rpe_dir=None):
        """Find the Phase 3 performance file for the specified RPE directory."""
        if rpe_dir is None:
            rpe_dir = self.rpe_dir if hasattr(self, 'rpe_dir') and self.rpe_dir else None
            if rpe_dir is None:
                # If none is specified, search the first RPE directory.
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
        """Find Phase 3 performance files for all RPEs."""
        rpe_perf_files = {}
        discovered_rpe_dirs = self._discover_rpe_dirs()
        logger.debug("Discovering RPE perf files in dirs: %s" % discovered_rpe_dirs)
        for rpe_dir in discovered_rpe_dirs:
            perf_file = self._find_rpe_perf_file(rpe_dir)
            if perf_file:
                # Extract rpe_id from the file name.
                filename = os.path.basename(perf_file)
                # Format: rpe_phase3_perf_{rpe_id}.json
                if filename.startswith("rpe_phase3_perf_") and filename.endswith(".json"):
                    rpe_id = filename[16:-5]  # Remove prefix and suffix.
                    rpe_perf_files[rpe_id] = perf_file
                    logger.debug("Found RPE perf file: %s -> %s" % (rpe_id, perf_file))
        logger.debug("Total RPE perf files found: %d" % len(rpe_perf_files))
        return rpe_perf_files
    
    def _find_ce_perf_file(self, ce_id):
        """Find CE performance files."""
        for ce_dir in self._discover_ce_dirs():
            perf_file = os.path.join(ce_dir, "performance_data", f"ce_perf_{ce_id}.json")
            if os.path.exists(perf_file):
                return perf_file
        return None

    def _find_ce_pre_connect_flag(self, ce_id):
        """Find CE pre-connect ready flag files: ce_pre_connect_ready_{ce_id}.flag."""
        ce_dirs = self._discover_ce_dirs()
        try:
            idx = int(ce_id.split("-")[1]) - 1
            if 0 <= idx < len(ce_dirs):
                flag_file = os.path.join(ce_dirs[idx], "performance_data", "ce_pre_connect_ready_%s.flag" % ce_id)
                if os.path.isfile(flag_file):
                    return flag_file
        except (ValueError, IndexError):
            pass
        for ce_dir in ce_dirs:
            flag_file = os.path.join(ce_dir, "performance_data", "ce_pre_connect_ready_%s.flag" % ce_id)
            if os.path.isfile(flag_file):
                return flag_file
        return None

    def wait_for_all_ces_pre_connect_ready(self, ce_ids, timeout=120):
        """Wait until all CEs are pre-connect ready and have written ready flags."""
        logger.info("Waiting for all CEs to be pre-connect ready...")
        start_time = time.time()
        ready = set()
        while len(ready) < len(ce_ids):
            if time.time() - start_time > timeout:
                logger.error("Timeout waiting for CEs pre-connect ready (%d/%d)" % (len(ready), len(ce_ids)))
                return False
            for ce_id in ce_ids:
                if ce_id in ready:
                    continue
                if self._find_ce_pre_connect_flag(ce_id) is not None:
                    ready.add(ce_id)
                    logger.info("CE %s pre-connect ready" % ce_id)
            time.sleep(0.2)
        logger.info("All %d CE(s) pre-connect ready. You can start RPE now." % len(ce_ids))
        return True

    def wait_for_ces_complete(self, ce_ids, timeout=300):
        """Wait until all CEs complete authentication."""
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

    def _get_issuing_rpe_perf_file(self):
        """Return the issuing RPE phase3 performance file path."""
        rpe_dir = None
        if hasattr(self, "rpe_dir") and self.rpe_dir and os.path.isdir(self.rpe_dir):
            rpe_dir = self.rpe_dir
        else:
            party1 = os.path.join(self.rpe_base_dir, "RPE_party1")
            if os.path.isdir(party1):
                rpe_dir = party1
            else:
                rpe_dirs = self._discover_rpe_dirs()
                if rpe_dirs:
                    rpe_dir = rpe_dirs[0]
        if rpe_dir is None:
            return None
        return self._find_rpe_perf_file(rpe_dir)

    def _read_all_issuing_rpe_authentications(self):
        """Read all CE authentication records from the issuing RPE performance file."""
        perf_file = self._get_issuing_rpe_perf_file()
        if not perf_file or not os.path.exists(perf_file):
            return []
        try:
            with open(perf_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.warning("Error reading issuing RPE perf file %s: %s" % (perf_file, e))
            return []
        if not isinstance(data, dict):
            return []
        return list(data.get("ce_authentications", []))

    def wait_for_auth_count_target(self, target_count, timeout=600):
        """Poll until the issuing RPE has at least target_count total CE authentication records."""
        perf_file = self._get_issuing_rpe_perf_file()
        logger.info(
            "Waiting for issuing RPE auth count target %d (perf file: %s)" %
            (target_count, perf_file or "unknown")
        )
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                logger.error(
                    "Timeout waiting for %d total CE authentication(s) on issuing RPE" % target_count
                )
                return False
            auths = self._read_all_issuing_rpe_authentications()
            if len(auths) >= target_count:
                logger.info(
                    "Issuing RPE has %d CE authentication record(s) (target %d)" %
                    (len(auths), target_count)
                )
                return True
            logger.debug(
                "Issuing RPE auth count %d < %d, waiting..." % (len(auths), target_count)
            )
            time.sleep(1)

    def _fmt_ms(self, val):
        if val is None:
            return "N/A"
        return "%.0fms" % float(val)

    def _stats_ms(self, values):
        if not values:
            return {"avg": None, "min": None, "max": None, "count": 0}
        return {
            "avg": sum(values) / len(values),
            "min": min(values),
            "max": max(values),
            "count": len(values),
        }

    def _max_peer_ms(self, peers_raw, field, accepted_only=False):
        """Return MAX of a peer timing field; prefer accepted peers, else all peers."""
        accepted = []
        all_values = []
        for peer in peers_raw.values():
            val = peer.get(field)
            if val is None:
                continue
            val = float(val)
            all_values.append(val)
            if peer.get("accepted"):
                accepted.append(val)
        if accepted_only:
            return max(accepted) if accepted else None
        source = accepted if accepted else all_values
        return max(source) if source else None

    def _select_bottleneck_peer(self, peers_raw, accepted_only=True):
        """Pick accepted peer with largest rpc_total_ms + local_verify_echo_ms (critical path)."""
        candidates = []
        for peer_id, peer in peers_raw.items():
            if not isinstance(peer, dict):
                continue
            if accepted_only and not peer.get("accepted"):
                continue
            rpc = peer.get("rpc_total_ms")
            verify = peer.get("local_verify_echo_ms")
            if rpc is None and verify is None:
                continue
            score = float(rpc or 0) + float(verify or 0)
            candidates.append((score, peer_id, peer))
        if not candidates and accepted_only:
            return self._select_bottleneck_peer(peers_raw, accepted_only=False)
        if not candidates:
            return None, None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1], candidates[0][2]

    def _peer_remote_veri_record_ms(self, peer):
        remote = peer.get("remote_timings") or {}
        verify_ms = remote.get("verify_state_signature_ms")
        record_ms = remote.get("record_state_ms")
        if verify_ms is None and record_ms is None:
            return None
        return float(verify_ms or 0) + float(record_ms or 0)

    def _max_peer_remote_veri_record_ms(self, peers_raw, accepted_only=True):
        """MAX(verify_state_signature_ms + record_state_ms) among peers."""
        values = []
        for peer in peers_raw.values():
            if accepted_only and not peer.get("accepted"):
                continue
            remote = peer.get("remote_timings") or {}
            verify_ms = remote.get("verify_state_signature_ms")
            record_ms = remote.get("record_state_ms")
            if verify_ms is None and record_ms is None:
                continue
            values.append(float(verify_ms or 0) + float(record_ms or 0))
        if not values and accepted_only:
            return self._max_peer_remote_veri_record_ms(peers_raw, accepted_only=False)
        return max(values) if values else None

    def _breakdown_table_columns(self):
        return [
            ("counter", "counter"),
            ("ce_id", "ce_id"),
            ("bottleneck_peer_id", "bottleneck_peer"),
            ("auth_total_ms", "auth_total"),
            ("quote_verify_ms", "quote_verify"),
            ("rpc_ms", "rpc(incl.remote.veri+record)"),
            ("remote_veri_record_ms", "remote.veri+record"),
            ("verify_echo_ms", "verify_echo"),
        ]

    def _write_breakdown_excel(self, xlsx_path, csv_path, breakdown_rows, breakdown_summary):
        columns = self._breakdown_table_columns()
        header_keys = [c[0] for c in columns]
        header_labels = [c[1] for c in columns]

        def row_values(row):
            out = []
            for key, _ in columns:
                val = row.get(key)
                if key in ("counter", "ce_id", "bottleneck_peer_id"):
                    out.append(val if val is not None else "")
                elif val is None:
                    out.append("")
                else:
                    out.append(round(float(val), 3))
            return out

        import csv
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header_labels)
            for row in breakdown_rows:
                writer.writerow(row_values(row))
            writer.writerow([])
            writer.writerow(["summary", "avg", "min", "max", "count"])
            for key, label in columns[2:]:
                s = breakdown_summary.get(key, {})
                writer.writerow([
                    label,
                    round(s["avg"], 3) if s.get("avg") is not None else "",
                    round(s["min"], 3) if s.get("min") is not None else "",
                    round(s["max"], 3) if s.get("max") is not None else "",
                    s.get("count", 0),
                ])

        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font
            wb = Workbook()
            ws = wb.active
            ws.title = "breakdown"
            ws.append(header_labels)
            for cell in ws[1]:
                cell.font = Font(bold=True)
            for row in breakdown_rows:
                ws.append(row_values(row))
            ws.append([])
            ws.append(["summary", "avg", "min", "max", "count"])
            for key, label in columns[2:]:
                s = breakdown_summary.get(key, {})
                ws.append([
                    label,
                    round(s["avg"], 3) if s.get("avg") is not None else None,
                    round(s["min"], 3) if s.get("min") is not None else None,
                    round(s["max"], 3) if s.get("max") is not None else None,
                    s.get("count", 0),
                ])
            wb.save(xlsx_path)
            return True
        except ImportError:
            return False

    def _extract_ft_breakdown_row(self, auth):
        timings = auth.get("ft_state_propagation_timings") or {}
        peers_raw = timings.get("peers") or {}
        peers = {}
        for peer_id, peer in peers_raw.items():
            remote = peer.get("remote_timings") or {}
            peers[peer_id] = {
                "address": peer.get("address"),
                "rpc_total_ms": peer.get("rpc_total_ms"),
                "local_verify_echo_ms": peer.get("local_verify_echo_ms"),
                "remote": {
                    "total_ms": remote.get("total_ms"),
                    "verify_state_signature_ms": remote.get("verify_state_signature_ms"),
                    "record_state_ms": remote.get("record_state_ms"),
                    "sign_echo_ms": remote.get("sign_echo_ms"),
                },
                "accepted": peer.get("accepted"),
                "error": peer.get("error"),
            }

        if timings.get("local_sign_state_ms") is not None or timings.get("local_sign_echo_ms") is not None:
            local_sign_ms = float(timings.get("local_sign_state_ms") or 0) + float(
                timings.get("local_sign_echo_ms") or 0
            )
        else:
            local_sign_ms = None

        bottleneck_peer_id, bottleneck_peer = self._select_bottleneck_peer(peers_raw, accepted_only=True)
        if bottleneck_peer is not None:
            rpc_ms = float(bottleneck_peer["rpc_total_ms"]) if bottleneck_peer.get("rpc_total_ms") is not None else None
            verify_echo_ms = (
                float(bottleneck_peer["local_verify_echo_ms"])
                if bottleneck_peer.get("local_verify_echo_ms") is not None
                else None
            )
            remote_veri_record_ms = self._peer_remote_veri_record_ms(bottleneck_peer)
        else:
            rpc_ms = None
            verify_echo_ms = None
            remote_veri_record_ms = None

        ft_total_ms = timings.get("total_ms")
        ft_total_ms = float(ft_total_ms) if ft_total_ms is not None else None

        if ft_total_ms is not None:
            ft_overhead_ms = max(
                0.0,
                ft_total_ms
                - (local_sign_ms or 0)
                - (rpc_ms or 0)
                - (verify_echo_ms or 0),
            )
        else:
            ft_overhead_ms = None

        auth_duration = auth.get("auth_duration")
        auth_total_ms = float(auth_duration) * 1000 if auth_duration is not None else None

        native = auth.get("stage3_native_quote_verification_duration")
        quote_verify_ms = float(native) * 1000 if native is not None else None

        policy = auth.get("stage3_expectation_policy_enforcement_duration")
        policy_ms = float(policy) * 1000 if policy is not None else None

        ft_wall = auth.get("ft_state_propagation_duration") or auth.get("ft_state_propagation")
        ft_wall_ms = float(ft_wall) * 1000 if ft_wall is not None else None

        if auth_total_ms is not None:
            other_ms = auth_total_ms - (quote_verify_ms or 0) - (policy_ms or 0) - (ft_wall_ms or 0)
        else:
            other_ms = None

        return {
            "counter": timings.get("attestation_counter"),
            "ce_id": auth.get("ce_id"),
            "auth_total_ms": auth_total_ms,
            "quote_verify_ms": quote_verify_ms,
            "policy_ms": policy_ms,
            "ft_wall_ms": ft_wall_ms,
            "ft_total_ms": ft_total_ms,
            "local_sign_ms": local_sign_ms,
            "bottleneck_peer_id": bottleneck_peer_id,
            "rpc_ms": rpc_ms,
            "remote_veri_record_ms": remote_veri_record_ms,
            "verify_echo_ms": verify_echo_ms,
            "ft_overhead_ms": ft_overhead_ms,
            "other_ms": other_ms,
            "peers": peers,
        }


    def collect_state_update_report(self, repeat):
        """Collect N new CE authentications from issuing RPE and write state update reports."""
        baseline_count = len(self._read_all_issuing_rpe_authentications())
        target_count = baseline_count + repeat
        logger.info(
            "State update collection: baseline %d, waiting for %d new CE authentications (target total %d)" %
            (baseline_count, repeat, target_count)
        )

        if not self.wait_for_auth_count_target(target_count):
            return None

        all_auths = self._read_all_issuing_rpe_authentications()
        auths = all_auths[baseline_count:baseline_count + repeat]

        breakdown_rows = [self._extract_ft_breakdown_row(auth) for auth in auths]
        breakdown_summary = {
            "auth_total_ms": self._stats_ms([r["auth_total_ms"] for r in breakdown_rows if r["auth_total_ms"] is not None]),
            "quote_verify_ms": self._stats_ms([r["quote_verify_ms"] for r in breakdown_rows if r["quote_verify_ms"] is not None]),
            "rpc_ms": self._stats_ms([r["rpc_ms"] for r in breakdown_rows if r["rpc_ms"] is not None]),
            "remote_veri_record_ms": self._stats_ms([r["remote_veri_record_ms"] for r in breakdown_rows if r["remote_veri_record_ms"] is not None]),
            "verify_echo_ms": self._stats_ms([r["verify_echo_ms"] for r in breakdown_rows if r["verify_echo_ms"] is not None]),
        }

        def _metric_values(auth_list, primary_key, fallback_key=None):
            values = []
            for auth in auth_list:
                val = auth.get(primary_key)
                if val is None and fallback_key:
                    val = auth.get(fallback_key)
                if val is not None:
                    values.append(float(val))
            return values

        def _stats(values):
            if not values:
                return {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}
            return {
                "avg": sum(values) / len(values),
                "min": min(values),
                "max": max(values),
                "count": len(values),
            }

        auth_durations = _metric_values(auths, "auth_duration")
        ft_durations = _metric_values(
            auths, "ft_state_propagation_duration", "ft_state_propagation"
        )
        stage3_native = _metric_values(auths, "stage3_native_quote_verification_duration")

        issuing_file = self._get_issuing_rpe_perf_file()
        result = {
            "baseline_authentication_count": baseline_count,
            "target_new_authentications": repeat,
            "collected_new_authentications": len(auths),
            "issuing_rpe_perf_file": issuing_file,
            "statistics": {
                "auth_duration": _stats(auth_durations),
                "ft_state_propagation_duration": _stats(ft_durations),
                "stage3_native_quote_verification_duration": _stats(stage3_native),
            },
            "ce_authentications": auths,
            "ft_breakdown_rows": breakdown_rows,
            "ft_breakdown_summary": breakdown_summary,
        }

        json_path = os.path.join(self.perf_dir, "state_update_report.json")
        txt_path = os.path.join(self.perf_dir, "state_update_report.txt")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        stats = result["statistics"]
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("State Update Collection Report (Issuing RPE CE Authentications)\n")
            f.write("=" * 80 + "\n\n")
            f.write("Baseline authentication count: %d\n" % baseline_count)
            f.write("Target new authentications: %d\n" % repeat)
            f.write("Collected new authentications: %d\n" % len(auths))
            if issuing_file:
                f.write("Issuing RPE perf file: %s\n\n" % issuing_file)
            for name, label in (
                ("auth_duration", "Auth Duration (s)"),
                ("ft_state_propagation_duration", "FT State Propagation (s)"),
                ("stage3_native_quote_verification_duration", "Stage3 Native Quote Verification (s)"),
            ):
                s = stats[name]
                f.write(
                    "%s — avg: %.6f, min: %.6f, max: %.6f, count: %d\n" %
                    (label, s["avg"], s["min"], s["max"], s["count"])
                )

            f.write("\n")
            f.write("-" * 80 + "\n")
            f.write("Authentication Breakdown (ms)\n")
            f.write("-" * 80 + "\n")
            f.write(
                "  Each row = one authentication. bottleneck_peer = slowest peer (rpc+verify_echo).\n"
                "  quote_verify = CE quote verification (before FT).\n"
                "  rpc(incl.remote.veri+record) = StateUpdate RPC round-trip incl. network + remote veri+record (subset below).\n"
                "  remote.veri+record = verify_state_signature + record_state on that peer (already inside rpc column).\n"
                "  verify_echo = local echo verify after rpc returns on that peer (sequential after rpc).\n"
            )
            f.write(
                "%8s %8s %14s %12s %12s %10s %18s %12s\n" %
                ("counter", "ce_id", "bottleneck_peer", "auth_total", "quote_verify", "rpc(incl.remote.veri+record)", "remote.veri+record", "verify_echo")
            )
            for row in breakdown_rows:
                f.write(
                    "%8s %8s %14s %12s %12s %10s %18s %12s\n" %
                    (
                        row["counter"] if row["counter"] is not None else "N/A",
                        row["ce_id"] or "N/A",
                        row.get("bottleneck_peer_id") or "N/A",
                        self._fmt_ms(row["auth_total_ms"]),
                        self._fmt_ms(row["quote_verify_ms"]),
                        self._fmt_ms(row["rpc_ms"]),
                        self._fmt_ms(row["remote_veri_record_ms"]),
                        self._fmt_ms(row["verify_echo_ms"]),
                    )
                )

            f.write("\nSummary (avg / min / max)\n")
            for key, label in (
                ("auth_total_ms", "auth_total"),
                ("quote_verify_ms", "quote_verify"),
                ("rpc_ms", "rpc(incl.remote.veri+record)"),
                ("remote_veri_record_ms", "remote.veri+record"),
                ("verify_echo_ms", "verify_echo"),
            ):
                s = breakdown_summary[key]
                if s["count"]:
                    f.write(
                        "  %-18s avg: %8s  min: %8s  max: %8s  (n=%d)\n" %
                        (
                            label,
                            self._fmt_ms(s["avg"]),
                            self._fmt_ms(s["min"]),
                            self._fmt_ms(s["max"]),
                            s["count"],
                        )
                    )
                else:
                    f.write("  %-18s N/A\n" % label)

        csv_path = os.path.join(self.perf_dir, "state_update_report.csv")
        xlsx_path = os.path.join(self.perf_dir, "state_update_report.xlsx")
        wrote_xlsx = self._write_breakdown_excel(xlsx_path, csv_path, breakdown_rows, breakdown_summary)

        logger.info("=" * 60)
        logger.info("State update report: %d new authentication(s) collected" % len(auths))
        for row in breakdown_rows[:5]:
            logger.info(
                "  breakdown: counter=%s ce_id=%s auth_total=%s quote_verify=%s rpc=%s "
                "peer=%s remote.veri+record=%s verify_echo=%s" %
                (
                    row["counter"] if row["counter"] is not None else "N/A",
                    row["ce_id"] or "N/A",
                    self._fmt_ms(row["auth_total_ms"]),
                    self._fmt_ms(row["quote_verify_ms"]),
                    self._fmt_ms(row["rpc_ms"]),
                    row.get("bottleneck_peer_id") or "N/A",
                    self._fmt_ms(row["remote_veri_record_ms"]),
                    self._fmt_ms(row["verify_echo_ms"]),
                )
            )
        logger.info(
            "  Auth Duration — avg: %.6f, min: %.6f, max: %.6f" %
            (stats["auth_duration"]["avg"], stats["auth_duration"]["min"], stats["auth_duration"]["max"])
        )
        logger.info(
            "  FT State Propagation — avg: %.6f, min: %.6f, max: %.6f" %
            (
                stats["ft_state_propagation_duration"]["avg"],
                stats["ft_state_propagation_duration"]["min"],
                stats["ft_state_propagation_duration"]["max"],
            )
        )
        logger.info(
            "  Stage3 Native Quote Verification — avg: %.6f, min: %.6f, max: %.6f" %
            (
                stats["stage3_native_quote_verification_duration"]["avg"],
                stats["stage3_native_quote_verification_duration"]["min"],
                stats["stage3_native_quote_verification_duration"]["max"],
            )
        )
        logger.info("  JSON: %s" % json_path)
        logger.info("  TXT: %s" % txt_path)
        logger.info("  CSV: %s" % csv_path)
        if wrote_xlsx:
            logger.info("  XLSX: %s" % xlsx_path)
        else:
            logger.info("  XLSX: skipped (install openpyxl for .xlsx; use CSV in Excel)")
        logger.info("=" * 60)
        return result

    def check_rpe_perf_data_ready(self, ce_ids):
        """
        Check whether RPE performance files contain authentication records for
        all CEs in this round. This compares the completed CE authentication
        count with the expected count N and returns True on match.
        """
        if not ce_ids:
            return False
        
        # Expected CE count.
        expected_count = len(ce_ids)
        
        # Find all RPE performance files.
        rpe_perf_files = self._find_all_rpe_perf_files()
        if not rpe_perf_files:
            logger.debug("No RPE perf files found")
            return False
        
        # Collect authenticated ce_id values from all RPE authentication records.
        all_ce_ids_found = set()
        
        for rpe_id, perf_file in rpe_perf_files.items():
            try:
                with open(perf_file, 'r') as f:
                    rpe_data = json.load(f)
                    if isinstance(rpe_data, dict) and "ce_authentications" in rpe_data:
                        for auth in rpe_data["ce_authentications"]:
                            if "ce_id" in auth:
                                all_ce_ids_found.add(auth["ce_id"])
            except Exception as e:
                logger.debug("Error reading RPE perf file %s: %s" % (perf_file, e))
                continue
        
        actual_count = len(all_ce_ids_found)
        
        # Compare authenticated CE count with the expected count.
        if actual_count == expected_count:
            logger.debug("RPE performance data is ready: %d CEs authenticated (expected %d)" % 
                        (actual_count, expected_count))
            return True
        else:
            logger.debug("RPE performance data not ready: %d CEs authenticated, expected %d" % 
                        (actual_count, expected_count))
            return False
    
    def collect_performance_data(self, ce_ids):
        """Collect performance data."""
        # Collect all RPE-side data.
        rpe_perf_files = self._find_all_rpe_perf_files()
        logger.debug("Found %d RPE perf files: %s" % (len(rpe_perf_files), list(rpe_perf_files.keys())))
        rpe_data_dict = {}
        for rpe_id, perf_file in rpe_perf_files.items():
            try:
                with open(perf_file, 'r') as f:
                    rpe_data_dict[rpe_id] = json.load(f)
                    logger.debug("Loaded RPE perf data for %s: %d authentications" % (
                        rpe_id, len(rpe_data_dict[rpe_id].get("ce_authentications", []))
                    ))
            except Exception as e:
                logger.warning("Error reading RPE perf file for %s: %s" % (rpe_id, e))
        
        # Preserve backward compatibility when there is only one RPE.
        rpe_data = rpe_data_dict if len(rpe_data_dict) > 1 else (list(rpe_data_dict.values())[0] if rpe_data_dict else None)
        logger.debug("RPE data type: %s, has ce_authentications: %s" % (
            type(rpe_data).__name__,
            isinstance(rpe_data, dict) and "ce_authentications" in rpe_data
        ))
        
        # Collect CE-side data.
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
    
    def run_test(self, num_ces, ce_first=False, total_time=False):
        """
        Run the performance test.
        This method does not start CEs; CEs should be started by start_multi_ce.py.
        ce_first=True waits for CE pre-connect readiness, signals RPE startup,
        waits for Enter after the user starts RPE, then waits for CE completion.
        total_time=True measures total authentication time across N CEs. Start
        CEs with CE_WAIT_FOR_START_RPE=1, wait for initialization, signal RPE
        startup, then write START_RPE_NOW.flag so CE-side timing starts.
        """
        logger.info("=" * 60)
        logger.info("Starting Phase 3 performance test with %d CEs" % num_ces)
        if total_time:
            logger.info("Mode: Total-time. Start CEs with CE_WAIT_FOR_START_RPE=1; script signals when to start RPE, then CE-side timing = first auth_start to last auth_end.")
        elif ce_first:
            logger.info("Mode: CE-first. Start all CEs first; script will signal when you can start RPE.")
        else:
            logger.info("Note: CEs should be started separately using start_multi_ce.py")
        logger.info("=" * 60)
        
        # Clean previous performance data and CE pre-connect flags.
        for ce_dir in self._discover_ce_dirs():
            perf_data_dir = os.path.join(ce_dir, "performance_data")
            if os.path.exists(perf_data_dir):
                for perf_file in glob.glob(os.path.join(perf_data_dir, "ce_perf_*.json")):
                    try:
                        os.remove(perf_file)
                    except Exception:
                        pass
                for flag_file in glob.glob(os.path.join(perf_data_dir, "ce_pre_connect_ready_*.flag")):
                    try:
                        os.remove(flag_file)
                    except Exception:
                        pass
                start_rpe_flag = os.path.join(perf_data_dir, "START_RPE_NOW.flag")
                if os.path.isfile(start_rpe_flag):
                    try:
                        os.remove(start_rpe_flag)
                    except Exception:
                        pass
        
        # Clean all RPE performance data.
        for rpe_dir in self._discover_rpe_dirs():
            rpe_perf_data_dir = os.path.join(rpe_dir, "performance_data")
            if os.path.exists(rpe_perf_data_dir):
                for perf_file in glob.glob(os.path.join(rpe_perf_data_dir, "rpe_phase3_perf_*.json")):
                    try:
                        os.remove(perf_file)
                        logger.debug("Removed RPE perf file: %s" % perf_file)
                    except Exception as e:
                        logger.warning("Failed to remove RPE perf file %s: %s" % (perf_file, e))
        
        # Generate the CE ID list.
        ce_ids = [f"ce-{i+1}" for i in range(num_ces)]
        ce_dirs = self._discover_ce_dirs()[:num_ces]
        
        if len(ce_dirs) < num_ces:
            logger.error("Not enough CE directories found. Need %d, found %d" % (num_ces, len(ce_dirs)))
            return None

        if ce_first or total_time:
            if not self.wait_for_all_ces_pre_connect_ready(ce_ids):
                logger.error("Not all CEs became pre-connect ready")
                return None
            _signal_msg = ">>> Signal: all CEs are initialized; start RPE now <<<"
            for _ in range(3):
                logger.info("")
            logger.info("=" * 60)
            logger.info(_signal_msg)
            logger.info("=" * 60)
            for _ in range(3):
                logger.info("")
            try:
                input("Press Enter after starting RPE... ")
            except EOFError:
                logger.info("(no stdin, waiting 10s...)")
                time.sleep(10)
            if total_time:
                for ce_dir in ce_dirs:
                    perf_data_dir = os.path.join(ce_dir, "performance_data")
                    start_rpe_flag = os.path.join(perf_data_dir, "START_RPE_NOW.flag")
                    try:
                        os.makedirs(perf_data_dir, exist_ok=True)
                        with open(start_rpe_flag, "w") as f:
                            f.write(_signal_msg + "\n")
                        logger.info("Created %s" % start_rpe_flag)
                    except Exception as e:
                        logger.warning("Failed to create START_RPE_NOW.flag in %s: %s" % (ce_dir, e))
                logger.info("START_RPE_NOW.flag created; CEs will start timing and connect to RPE.")

        # Wait until all CEs complete authentication.
        logger.info("Waiting for all CEs to complete authentication...")
        success = self.wait_for_ces_complete(ce_ids, timeout=300)
        if not success:
            logger.error("Test failed: not all CEs completed authentication")
            return None
        
        # Check whether RPE performance data is ready by counting authenticated CEs.
        logger.info("Checking if RPE performance data is ready...")
        if not self.check_rpe_perf_data_ready(ce_ids):
            logger.warning("RPE performance data may not be complete (CE count mismatch), proceeding anyway...")
        
        # Collect performance data.
        rpe_data, ce_data = self.collect_performance_data(ce_ids)
        
        # Extract all CE authentication durations from RPE data.
        rpe_auth_durations = []
        stage3_native_quote_verification_durations = []
        stage3_expectation_policy_enforcement_durations = []
        ft_state_propagation_durations = []
        all_rpe_ce_auths = []
        first_auth_start = None
        last_auth_end = None
        
        # Aggregate authentication data from all RPEs.
        if rpe_data:
            if isinstance(rpe_data, dict) and "ce_authentications" in rpe_data:
                # Single-RPE case.
                all_rpe_ce_auths = rpe_data["ce_authentications"]
            elif isinstance(rpe_data, dict):
                # Multi-RPE case: dictionary keyed by rpe_id.
                for rpe_id, rpe_info in rpe_data.items():
                    if isinstance(rpe_info, dict) and "ce_authentications" in rpe_info:
                        all_rpe_ce_auths.extend(rpe_info["ce_authentications"])
        
        # Collect each CE's auth_duration and calculate total time from RPE-side data by default.
        if all_rpe_ce_auths:
            # Collect all auth_duration values.
            for auth in all_rpe_ce_auths:
                if auth.get("auth_duration") is not None:
                    rpe_auth_durations.append(auth["auth_duration"])
                native_duration = auth.get("stage3_native_quote_verification_duration")
                policy_duration = auth.get("stage3_expectation_policy_enforcement_duration")
                if native_duration is not None:
                    stage3_native_quote_verification_durations.append(native_duration)
                if policy_duration is not None:
                    stage3_expectation_policy_enforcement_durations.append(policy_duration)
                ft_duration = auth.get("ft_state_propagation_duration")
                if ft_duration is not None:
                    ft_state_propagation_durations.append(ft_duration)
            
            # Find first auth_start and last auth_end on the RPE side.
            valid_auths = [auth for auth in all_rpe_ce_auths 
                          if auth.get("auth_start") is not None and auth.get("auth_end") is not None]
            if valid_auths:
                first_auth_start = min(auth.get("auth_start", float('inf')) for auth in valid_auths)
                last_auth_end = max(auth.get("auth_end", 0) for auth in valid_auths)
        
        # --total-time mode: calculate Total Time from CE-side auth_start/auth_end.
        if total_time and ce_data:
            ce_valid = [(ce_id, ce_data[ce_id]) for ce_id in ce_ids if ce_id in ce_data 
                        and ce_data[ce_id].get("auth_start") is not None and ce_data[ce_id].get("auth_end") is not None]
            if ce_valid:
                first_auth_start = min(ce_data[ce_id].get("auth_start", float('inf')) for ce_id, _ in ce_valid)
                last_auth_end = max(ce_data[ce_id].get("auth_end", 0) for ce_id, _ in ce_valid)
                logger.info("Total Time (--total-time) computed from CE-side perf files (first CE auth_start to last CE auth_end)")
        
        # Calculate average auth_duration.
        avg_auth_duration = sum(rpe_auth_durations) / len(rpe_auth_durations) if rpe_auth_durations else 0
        
        # Calculate total time from first auth_start to last auth_end.
        rpe_total_time = None
        first_auth_start_time = None
        last_auth_start_time = None
        first_auth_end_time = None
        last_auth_end_time = None
        
        if first_auth_start is not None and last_auth_end is not None and first_auth_start != float('inf') and last_auth_end > 0:
            rpe_total_time = last_auth_end - first_auth_start
            # Calculate the time span between first auth_start and last auth_end.
            if total_time and ce_data:
                ce_valid = [(ce_id, ce_data[ce_id]) for ce_id in ce_ids if ce_id in ce_data 
                            and ce_data[ce_id].get("auth_start") is not None and ce_data[ce_id].get("auth_end") is not None]
                if ce_valid:
                    first_auth_start_time = min(ce_data[ce_id].get("auth_start", float('inf')) for ce_id, _ in ce_valid)
                    last_auth_start_time = max(ce_data[ce_id].get("auth_start", 0) for ce_id, _ in ce_valid)
                    first_auth_end_time = min(ce_data[ce_id].get("auth_end", float('inf')) for ce_id, _ in ce_valid)
                    last_auth_end_time = max(ce_data[ce_id].get("auth_end", 0) for ce_id, _ in ce_valid)
            elif all_rpe_ce_auths:
                valid_auths = [auth for auth in all_rpe_ce_auths 
                              if auth.get("auth_start") is not None and auth.get("auth_end") is not None]
                if valid_auths:
                    first_auth_start_time = min(auth.get("auth_start", float('inf')) for auth in valid_auths)
                    last_auth_start_time = max(auth.get("auth_start", 0) for auth in valid_auths)
                    first_auth_end_time = min(auth.get("auth_end", float('inf')) for auth in valid_auths)
                    last_auth_end_time = max(auth.get("auth_end", 0) for auth in valid_auths)
        
        # Calculate CE start-time spread from first auth_start to last auth_start.
        ce_start_time_spread = None
        if first_auth_start_time is not None and last_auth_start_time is not None:
            ce_start_time_spread = last_auth_start_time - first_auth_start_time
        
        # Calculate processing-time range from first auth_end to last auth_end.
        processing_time_range = None
        if first_auth_end_time is not None and last_auth_end_time is not None:
            processing_time_range = last_auth_end_time - first_auth_end_time
        
        # Calculate throughput using the sum of all CE auth_duration values.
        throughput = 0
        total_auth_duration = sum(rpe_auth_durations) if rpe_auth_durations else 0
        if total_auth_duration > 0:
            # Throughput = CE count / total authentication processing time * 60.
            throughput = (num_ces / total_auth_duration) * 60
        elif rpe_total_time is not None and rpe_total_time > 0:
            # If RPE data is unavailable, fall back to total time.
            throughput = (num_ces / rpe_total_time) * 60
        
        # If RPE data is unavailable.
        if not rpe_auth_durations:
            logger.warning("RPE performance data not available, no authentication records found")
            rpe_total_time = 0
        
        result = {
            "num_ces": num_ces,
            "ce_ids": ce_ids,
            "first_auth_start": first_auth_start,
            "last_auth_end": last_auth_end,
            "rpe_total_time": rpe_total_time,  # Total time from first auth_start to last auth_end, including start-time spread.
            "ce_start_time_spread": ce_start_time_spread,  # CE start-time spread from first auth_start to last auth_start.
            "processing_time_range": processing_time_range,  # Processing-time range from first auth_end to last auth_end.
            "total_auth_duration": total_auth_duration,  # Sum of all CE auth_duration values, i.e. pure processing time.
            "throughput_per_minute": throughput,
            "individual_perf": ce_data,
            "rpe_perf": rpe_data,
            "statistics": {
                "avg_auth_duration": avg_auth_duration,  # Average auth_duration across N CEs.
                "auth_duration": {
                    "avg": avg_auth_duration,
                    "min": min(rpe_auth_durations) if rpe_auth_durations else 0,
                    "max": max(rpe_auth_durations) if rpe_auth_durations else 0,
                    "count": len(rpe_auth_durations)  # Number of authentication records actually collected.
                },
                "stage3_native_quote_verification": {
                    "avg": sum(stage3_native_quote_verification_durations) / len(stage3_native_quote_verification_durations)
                    if stage3_native_quote_verification_durations else 0,
                    "min": min(stage3_native_quote_verification_durations) if stage3_native_quote_verification_durations else 0,
                    "max": max(stage3_native_quote_verification_durations) if stage3_native_quote_verification_durations else 0,
                    "count": len(stage3_native_quote_verification_durations)
                },
                "stage3_expectation_policy_enforcement": {
                    "avg": sum(stage3_expectation_policy_enforcement_durations) / len(stage3_expectation_policy_enforcement_durations)
                    if stage3_expectation_policy_enforcement_durations else 0,
                    "min": min(stage3_expectation_policy_enforcement_durations) if stage3_expectation_policy_enforcement_durations else 0,
                    "max": max(stage3_expectation_policy_enforcement_durations) if stage3_expectation_policy_enforcement_durations else 0,
                    "count": len(stage3_expectation_policy_enforcement_durations)
                },
                "ft_state_propagation": {
                    "avg": sum(ft_state_propagation_durations) / len(ft_state_propagation_durations)
                    if ft_state_propagation_durations else 0,
                    "min": min(ft_state_propagation_durations) if ft_state_propagation_durations else 0,
                    "max": max(ft_state_propagation_durations) if ft_state_propagation_durations else 0,
                    "count": len(ft_state_propagation_durations)
                }
            }
        }
        
        # Save results.
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
            if total_time:
                logger.info("  Total Time (CE-side: first auth_start to last auth_end): %.3f seconds" % rpe_total_time)
            else:
                logger.info("  Total Time (first auth_start to last auth_end): %.3f seconds" % rpe_total_time)
        if ce_start_time_spread is not None:
            logger.info("  CE Start Time Spread (startup delay): %.3f seconds" % ce_start_time_spread)
        if processing_time_range is not None:
            logger.info("  Processing Time Range (first to last auth_end): %.3f seconds" % processing_time_range)
        if total_auth_duration > 0:
            logger.info("  Total Auth Duration (sum of all CE processing): %.3f seconds" % total_auth_duration)
        logger.info("  Throughput: %.2f CEs/minute (based on total auth_duration)" % throughput)
        if rpe_auth_durations:
            logger.info("  Average Auth Duration (RPE-side): %.3f seconds" % avg_auth_duration)
            if total_auth_duration > 0:
                logger.info("  Total Auth Duration (sum of all): %.3f seconds" % total_auth_duration)
            logger.info("  Auth Duration - Min: %.3f, Max: %.3f, Count: %d" % (
                result["statistics"]["auth_duration"]["min"],
                result["statistics"]["auth_duration"]["max"],
                result["statistics"]["auth_duration"]["count"]
            ))
            logger.info("  Stage 3 Native Quote Verification - Avg: %.3f, Min: %.3f, Max: %.3f" % (
                result["statistics"]["stage3_native_quote_verification"]["avg"],
                result["statistics"]["stage3_native_quote_verification"]["min"],
                result["statistics"]["stage3_native_quote_verification"]["max"]
            ))
            if result["statistics"]["ft_state_propagation"]["count"] > 0:
                logger.info("  SRAS-FT State Propagation - Avg: %.3f, Min: %.3f, Max: %.3f" % (
                    result["statistics"]["ft_state_propagation"]["avg"],
                    result["statistics"]["ft_state_propagation"]["min"],
                    result["statistics"]["ft_state_propagation"]["max"]
                ))
            logger.info("  Stage 3 Expectation-Policy Enforcement - Avg: %.3f, Min: %.3f, Max: %.3f" % (
                result["statistics"]["stage3_expectation_policy_enforcement"]["avg"],
                result["statistics"]["stage3_expectation_policy_enforcement"]["min"],
                result["statistics"]["stage3_expectation_policy_enforcement"]["max"]
            ))
        else:
            logger.warning("  No RPE authentication data found")
        logger.info("  Result saved to: %s" % result_file)
        logger.info("=" * 60)
        
        return result
    
    def run_series(self, start=1, end=10, ce_first=False, total_time=False):
        """Run a series of tests."""
        all_results = []
        
        for num_ces in range(start, end + 1):
            result = self.run_test(num_ces, ce_first=ce_first, total_time=total_time)
            if result:
                all_results.append(result)
            time.sleep(5)  # Interval between tests.
        
        # Generate the summary report.
        self.generate_summary_report(all_results)
        
        return all_results
    
    def generate_summary_report(self, all_results):
        """Generate the summary report."""
        import csv
        
        # Generate the CSV file.
        csv_file = os.path.join(self.perf_dir, "phase3_summary_report.csv")
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write the header.
            writer.writerow([
                "Repeat",
                "Number of CEs",
                "First Auth Start",
                "Last Auth End",
                "Total Time (s)",
                "CE Start Time Spread (s)",
                "Processing Time Range (s)",
                "Total Auth Duration (s)",
                "Avg Auth Duration (s)",
                "Min Auth Duration (s)",
                "Max Auth Duration (s)",
                "Stage3 Native Quote Verification Avg (s)",
                "Stage3 Native Quote Verification Min (s)",
                "Stage3 Native Quote Verification Max (s)",
                "Stage3 Expectation-Policy Enforcement Avg (s)",
                "Stage3 Expectation-Policy Enforcement Min (s)",
                "Stage3 Expectation-Policy Enforcement Max (s)",
                "SRAS-FT State Propagation Avg (s)",
                "SRAS-FT State Propagation Min (s)",
                "SRAS-FT State Propagation Max (s)",
                "SRAS-FT State Propagation Count",
                "Auth Count",
                "Throughput (CEs/min)"
            ])
            
            # Write data rows.
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_duration"]
                stage3_native_stats = result["statistics"]["stage3_native_quote_verification"]
                stage3_policy_stats = result["statistics"]["stage3_expectation_policy_enforcement"]
                ft_stats = result["statistics"].get("ft_state_propagation", {})
                rpe_total_time = result.get("rpe_total_time", 0)
                first_start = result.get("first_auth_start", 0)
                last_end = result.get("last_auth_end", 0)
                ce_start_spread = result.get("ce_start_time_spread")
                processing_range = result.get("processing_time_range")
                total_auth_duration = result.get("total_auth_duration", 0)
                
                writer.writerow([
                    result.get("repeat", 1),
                    num_ces,
                    "%.3f" % first_start if first_start else "N/A",
                    "%.3f" % last_end if last_end else "N/A",
                    "%.3f" % rpe_total_time if rpe_total_time else "N/A",
                    "%.3f" % ce_start_spread if ce_start_spread is not None else "N/A",
                    "%.3f" % processing_range if processing_range is not None else "N/A",
                    "%.3f" % total_auth_duration if total_auth_duration else "N/A",
                    "%.3f" % stats.get("avg", 0),
                    "%.3f" % stats.get("min", 0),
                    "%.3f" % stats.get("max", 0),
                    "%.3f" % stage3_native_stats.get("avg", 0),
                    "%.3f" % stage3_native_stats.get("min", 0),
                    "%.3f" % stage3_native_stats.get("max", 0),
                    "%.3f" % stage3_policy_stats.get("avg", 0),
                    "%.3f" % stage3_policy_stats.get("min", 0),
                    "%.3f" % stage3_policy_stats.get("max", 0),
                    "%.3f" % ft_stats.get("avg", 0),
                    "%.3f" % ft_stats.get("min", 0),
                    "%.3f" % ft_stats.get("max", 0),
                    ft_stats.get("count", 0),
                    stats.get("count", 0),
                    "%.2f" % result["throughput_per_minute"]
                ])
        
        # Generate the text report.
        report_file = os.path.join(self.perf_dir, "phase3_summary_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("Phase 3 Performance Test Summary (RPE Authentication of CEs)\n")
            f.write("=" * 100 + "\n\n")
            
            f.write("Repeat | Number | First Auth  | Last Auth   | Total Time | Start Spread| Proc Range  | Total Auth | Avg Auth   | Min Auth   | Max Auth   | Native Avg | Policy Avg | FT Prop Avg| Count | Throughput\n")
            f.write("       | of CEs | Start        | End          | (s)        | (s)         | (s)         | Duration(s)| Duration(s)| Duration(s)| Duration(s)| Duration(s)| Duration(s)| Duration(s)|       | (CEs/min)\n")
            f.write("-" * 181 + "\n")
            
            for result in all_results:
                num_ces = result["num_ces"]
                stats = result["statistics"]["auth_duration"]
                stage3_native_stats = result["statistics"]["stage3_native_quote_verification"]
                stage3_policy_stats = result["statistics"]["stage3_expectation_policy_enforcement"]
                ft_stats = result["statistics"].get("ft_state_propagation", {})
                rpe_total_time = result.get("rpe_total_time", 0)
                first_start = result.get("first_auth_start", 0)
                last_end = result.get("last_auth_end", 0)
                ce_start_spread = result.get("ce_start_time_spread")
                processing_range = result.get("processing_time_range")
                total_auth_duration = result.get("total_auth_duration", 0)
                
                f.write("%6d | %6d | %12.3f | %12.3f | %10.3f | %11.3f | %11.3f | %11.3f | %10.3f | %10.3f | %10.3f | %10.3f | %10.3f | %10.3f | %5d | %10.2f\n" % (
                    result.get("repeat", 1),
                    num_ces,
                    first_start if first_start else 0,
                    last_end if last_end else 0,
                    rpe_total_time if rpe_total_time else 0,
                    ce_start_spread if ce_start_spread is not None else 0,
                    processing_range if processing_range is not None else 0,
                    total_auth_duration if total_auth_duration else 0,
                    stats.get("avg", 0),
                    stats.get("min", 0),
                    stats.get("max", 0),
                    stage3_native_stats.get("avg", 0),
                    stage3_policy_stats.get("avg", 0),
                    ft_stats.get("avg", 0),
                    stats.get("count", 0),
                    result["throughput_per_minute"]
                ))
        
        logger.info("Summary report (CSV) saved to: %s" % csv_file)
        logger.info("Summary report (TXT) saved to: %s" % report_file)
    
    def generate_report_from_json_files(self, perf_dir=None):
        """
        Read generated phase3_test_result_Nces.json files and generate a summary report.
        """
        if perf_dir is None:
            perf_dir = self.perf_dir
        
        logger.info("=" * 60)
        logger.info("Generating summary report from existing JSON files...")
        logger.info("Searching in directory: %s" % perf_dir)
        logger.info("=" * 60)
        
        # Find all phase3_test_result_*ces.json files.
        json_files = glob.glob(os.path.join(perf_dir, "phase3_test_result_*ces.json"))
        
        if not json_files:
            logger.error("No phase3_test_result_*ces.json files found in %s" % perf_dir)
            return
        
        # Sort by CE count.
        def extract_num_ces(filename):
            import re
            match = re.search(r'phase3_test_result_(\d+)ces\.json', filename)
            return int(match.group(1)) if match else 0
        
        json_files.sort(key=extract_num_ces)
        logger.info("Found %d result files" % len(json_files))
        
        # Read all results.
        all_results = []
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    result = json.load(f)
                    all_results.append(result)
                    logger.info("Loaded: %s (N=%d CEs)" % (os.path.basename(json_file), result.get("num_ces", 0)))
            except Exception as e:
                logger.warning("Failed to load %s: %s" % (json_file, e))
                continue
        
        if not all_results:
            logger.error("No valid results loaded")
            return
        
        logger.info("Successfully loaded %d test results" % len(all_results))
        
        # Generate the summary report.
        self.generate_summary_report(all_results)
        
        logger.info("=" * 60)
        logger.info("Summary report generated successfully!")
        logger.info("=" * 60)




if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 3 Performance Test")
    parser.add_argument("--start", type=int, default=1, help="Starting number of CEs")
    parser.add_argument("--end", type=int, default=10, help="Ending number of CEs")
    parser.add_argument("--single", type=int, default=None, help="Test with a single number of CEs")
    parser.add_argument("--perf-dir", type=str, default="./performance_data", help="Performance data directory")
    parser.add_argument("--rpe-dir", type=str, default=None, help="Issuing RPE for current FT rpe_phase3_perf_*.json (default: discover RPE_party1 or first RPE)")
    parser.add_argument("--ce-base-dir", type=str, default=None, help="CE base directory")
    parser.add_argument("--ce-first", action="store_true", help="CE-first mode: start CEs first, script signals when to start RPE, then wait for auth complete")
    parser.add_argument("--total-time", action="store_true", help="N CE auth total-time mode: start CEs with CE_WAIT_FOR_START_RPE=1, signal when CE init done, after you start RPE and Enter script creates START_RPE_NOW.flag, CE-side timing = first auth_start to last auth_end")
    parser.add_argument("--generate-report", action="store_true", help="Generate summary report from existing JSON files")
    parser.add_argument(
        "--repeat",
        type=int,
        default=None,
        help="Collect N total CE authentications from issuing RPE perf; writes state_update_report to --perf-dir",
    )

    args = parser.parse_args()

    if args.repeat is not None:
        if args.repeat < 1:
            parser.error("--repeat must be >= 1")
        test = Phase3PerformanceTest(perf_dir=args.perf_dir, rpe_dir=args.rpe_dir)
        result = test.collect_state_update_report(args.repeat)
        sys.exit(0 if result else 1)

    test = Phase3PerformanceTest(
        perf_dir=args.perf_dir,
        rpe_dir=args.rpe_dir,
        ce_base_dir=args.ce_base_dir
    )

    if args.generate_report:
        # Generate a report from existing JSON files.
        test.generate_report_from_json_files(args.perf_dir)
    elif args.single:
        test.run_test(args.single, ce_first=args.ce_first, total_time=args.total_time)
    else:
        test.run_series(start=args.start, end=args.end, ce_first=args.ce_first, total_time=args.total_time)
