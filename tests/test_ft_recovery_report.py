import json
import os
import subprocess
import sys
import tempfile
import unittest


class FTRecoveryReportTest(unittest.TestCase):
    def _write_recovery_result(self, directory, rpe_id, total_ms, query_ms):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "rpe_ft_recovery_perf_%s.json" % rpe_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "total_recovery_ms": total_ms,
                    "recovery_query_ms": query_ms,
                    "evidence_quote_verification_ms": 2.0,
                    "signed_state_verification_ms": 3.0,
                    "counter_selection_ms": 0.5,
                    "new_quote_generation_ms": 4.0,
                    "new_quote_broadcast_ms": 0.2,
                    "valid_response_count": 2,
                    "quorum": 2,
                },
                f,
            )

    def test_generates_q2_report_grouped_by_num_rpes(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(repo_root, "performance", "q2_ft_recovery_test.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            n2_dir = os.path.join(temp_dir, "q2_n2")
            n4_dir = os.path.join(temp_dir, "q2_n4")
            output_dir = os.path.join(temp_dir, "out")
            self._write_recovery_result(n2_dir, "rpe-1", total_ms=10.0, query_ms=5.0)
            self._write_recovery_result(n2_dir, "rpe-2", total_ms=20.0, query_ms=7.0)
            self._write_recovery_result(n4_dir, "rpe-1", total_ms=30.0, query_ms=9.0)

            subprocess.run(
                [
                    sys.executable,
                    script,
                    "--input",
                    "n2=%s" % n2_dir,
                    "--input",
                    "n4=%s" % n4_dir,
                    "--output-dir",
                    output_dir,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            with open(os.path.join(output_dir, "q2_ft_recovery_report.json"), "r", encoding="utf-8") as f:
                rows = json.load(f)
            self.assertEqual(rows[0]["num_rpes"], 2)
            self.assertEqual(rows[0]["runs"], 2)
            self.assertEqual(rows[0]["total_recovery_ms"], 15.0)
            self.assertEqual(rows[0]["recovery_query_ms"], 6.0)
            self.assertEqual(rows[1]["num_rpes"], 4)


if __name__ == "__main__":
    unittest.main()
