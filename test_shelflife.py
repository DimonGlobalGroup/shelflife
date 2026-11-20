#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "shelflife.py")
NOW = 1700000000.0
DAY = 86400


def run(args, cwd=None):
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, cwd=cwd)


def write(path, data, age_days):
    with open(path, "wb") as fh:
        fh.write(data)
    ts = NOW - age_days * DAY
    os.utime(path, (ts, ts))


class ShelfLifeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def scan_json(self, extra=None):
        args = ["scan", self.root, "--json", "--now", str(NOW),
                "--stale-days", "365", "--large-bytes", "100"]
        if extra:
            args += extra
        r = run(args)
        return r, json.loads(r.stdout) if r.stdout.strip() else {}

    def test_fresh_file_no_findings(self):
        write(os.path.join(self.root, "fresh.txt"), b"hello", 10)
        r, data = self.scan_json()
        self.assertEqual(r.returncode, 0)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["reclaimable_bytes"], 0)

    def test_stale_file(self):
        write(os.path.join(self.root, "old.txt"), b"x" * 11, 400)
        r, data = self.scan_json()
        rules = [(f["rule"], f["severity"]) for f in data["findings"]]
        self.assertIn(("stale-file", "medium"), rules)
        self.assertEqual(data["reclaimable_bytes"], 11)

    def test_large_stale_is_high_and_reclaimable_once(self):
        write(os.path.join(self.root, "big.bin"), b"x" * 150, 400)
        r, data = self.scan_json()
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("large-file", rules)
        self.assertIn("stale-file", rules)
        self.assertIn("large-stale", rules)
        # Counted once despite three rules.
        self.assertEqual(data["reclaimable_bytes"], 150)
        self.assertEqual(r.returncode, 1)

    def test_large_fresh_not_reclaimable(self):
        write(os.path.join(self.root, "big.bin"), b"x" * 150, 5)
        r, data = self.scan_json()
        rules = [f["rule"] for f in data["findings"]]
        self.assertEqual(rules, ["large-file"])
        self.assertEqual(data["reclaimable_bytes"], 0)
        self.assertEqual(r.returncode, 0)

    def test_empty_file_and_empty_dir(self):
        write(os.path.join(self.root, "empty.txt"), b"", 5)
        os.mkdir(os.path.join(self.root, "vacant"))
        r, data = self.scan_json()
        rules = sorted(f["rule"] for f in data["findings"])
        self.assertEqual(rules, ["empty-dir", "empty-file"])

    def test_temp_residue(self):
        write(os.path.join(self.root, "notes.txt.bak"), b"data", 5)
        write(os.path.join(self.root, "scratch.tmp"), b"data", 5)
        r, data = self.scan_json()
        rules = [f["rule"] for f in data["findings"]]
        self.assertEqual(rules.count("temp-residue"), 2)

    def test_symlink_never_followed(self):
        target = os.path.join(self.root, "real.txt")
        write(target, b"x" * 11, 400)
        os.symlink(target, os.path.join(self.root, "link.txt"))
        r, data = self.scan_json()
        self.assertEqual(data["symlinks_skipped"], 1)
        paths = [f["path"] for f in data["findings"]]
        self.assertNotIn(os.path.join(self.root, "link.txt"), paths)

    def test_determinism_json_byte_identical(self):
        write(os.path.join(self.root, "old.txt"), b"x" * 11, 400)
        args = ["scan", self.root, "--json", "--now", str(NOW),
                "--stale-days", "365", "--large-bytes", "100"]
        a = run(args)
        b = run(args)
        self.assertEqual(a.stdout, b.stdout)

    def test_read_only(self):
        p = os.path.join(self.root, "old.txt")
        write(p, b"x" * 11, 400)
        before = sorted(os.listdir(self.root))
        mtime_before = os.stat(p).st_mtime
        self.scan_json()
        self.assertEqual(sorted(os.listdir(self.root)), before)
        self.assertEqual(os.stat(p).st_mtime, mtime_before)

    def test_missing_root_exit2_no_traceback(self):
        r = run(["scan", os.path.join(self.root, "nope"), "--now", str(NOW)])
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)

    def test_bad_option_exit2(self):
        r = run(["scan", self.root, "--min-severity", "bogus"])
        self.assertEqual(r.returncode, 2)
        r2 = run(["scan", self.root, "--stale-days", "-1", "--now", str(NOW)])
        self.assertEqual(r2.returncode, 2)
        r3 = run(["scan", self.root, "--large-bytes", "0", "--now", str(NOW)])
        self.assertEqual(r3.returncode, 2)

    def test_min_severity_filters(self):
        write(os.path.join(self.root, "empty.txt"), b"", 5)
        r, data = self.scan_json(extra=["--min-severity", "high"])
        self.assertEqual(data["findings"], [])

    def test_fail_on_never_and_medium(self):
        write(os.path.join(self.root, "old.txt"), b"x" * 11, 400)
        r, _ = self.scan_json(extra=["--fail-on", "never"])
        self.assertEqual(r.returncode, 0)
        r2, _ = self.scan_json(extra=["--fail-on", "medium"])
        self.assertEqual(r2.returncode, 1)

    def test_future_file_not_stale(self):
        p = os.path.join(self.root, "future.txt")
        with open(p, "wb") as fh:
            fh.write(b"hello")
        future = NOW + 10 * DAY
        os.utime(p, (future, future))
        r, data = self.scan_json()
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["reclaimable_bytes"], 0)

    def test_content_never_opened_binary_stale(self):
        # Undecodable binary content must scan fine: contents never opened.
        write(os.path.join(self.root, "blob.bin"), bytes(range(256)), 400)
        r, data = self.scan_json()
        self.assertEqual(r.returncode, 1)
        self.assertIn("stale-file", [f["rule"] for f in data["findings"]])

    def test_text_example_shape(self):
        write(os.path.join(self.root, "big.bin"), b"x" * 150, 400)
        r = run(["scan", self.root, "--now", str(NOW),
                 "--stale-days", "365", "--large-bytes", "100"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("shelflife: 1 dirs scanned, 1 files, 3 findings "
                      "(1 high, 1 medium, 1 low), 150 reclaimable bytes",
                      r.stdout)


if __name__ == "__main__":
    unittest.main()
