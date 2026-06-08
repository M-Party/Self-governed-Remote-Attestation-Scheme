import json
import os
import subprocess
import sys
import tempfile
import unittest


class FTOverheadReportTest(unittest.TestCase):
    def _write_result(self, directory, auth_avg, total_time, ft_prop=0.0):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "phase3_test_result_1ces.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "rpe_total_time": total_time,
                    "statistics": {
                        "auth_duration": {"avg": auth_avg},
                        "ft_state_propagation": {"avg": ft_prop},
                    },
                },
                f,
            )

    def test_baseline_dir_defaults_to_performance_data(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(repo_root, "performance", "ft_overhead_report.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_dir = os.path.join(temp_dir, "performance_data")
            ft_dir = os.path.join(temp_dir, "ft")
            output_dir = os.path.join(temp_dir, "out")
            self._write_result(baseline_dir, auth_avg=0.2, total_time=0.25)
            self._write_result(ft_dir, auth_avg=0.3, total_time=0.4, ft_prop=0.08)

            subprocess.run(
                [
                    sys.executable,
                    script,
                    "--ft-dir",
                    ft_dir,
                    "--output-dir",
                    output_dir,
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            report_path = os.path.join(output_dir, "sras_ft_overhead_report.json")
            with open(report_path, "r", encoding="utf-8") as f:
                rows = json.load(f)
            self.assertEqual(rows[0]["baseline_avg_auth_s"], 0.2)
            self.assertEqual(rows[0]["ft_avg_auth_s"], 0.3)


if __name__ == "__main__":
    unittest.main()
