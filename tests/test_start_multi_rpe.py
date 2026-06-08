import os
import tempfile
import unittest

from performance.start_multi_rpe import RPEStarter


class RPEStarterCleanupTest(unittest.TestCase):
    def test_cleanup_ft_cache_files_removes_all_party_cache_locations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            expected_removed = []
            expected_kept = []
            for party_id in range(1, 3):
                rpe_dir = os.path.join(temp_dir, "RPE_party%d" % party_id)
                for subdir in ("collaterals", "performance_data"):
                    os.makedirs(os.path.join(rpe_dir, subdir), exist_ok=True)
                    for filename in ("expt_cache.json", "ft_counter_cache.json"):
                        path = os.path.join(rpe_dir, subdir, filename)
                        with open(path, "w", encoding="utf-8") as f:
                            f.write("{}")
                        expected_removed.append(path)
                kept_path = os.path.join(rpe_dir, "performance_data", "rpe_phase3_perf_rpe-%d.json" % party_id)
                with open(kept_path, "w", encoding="utf-8") as f:
                    f.write("{}")
                expected_kept.append(kept_path)

            starter = RPEStarter(base_dir=temp_dir, num_parties=2)
            starter.cleanup_ft_cache_files()

            for path in expected_removed:
                self.assertFalse(os.path.exists(path), path)
            for path in expected_kept:
                self.assertTrue(os.path.exists(path), path)


if __name__ == "__main__":
    unittest.main()
