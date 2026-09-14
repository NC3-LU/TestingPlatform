from pathlib import Path
import os, shutil, sqlite3, subprocess, tempfile, unittest


class StartGuardTests(unittest.TestCase):
    def test_missing_database_refuses_start_without_creating_it(self):
        script = Path(__file__).resolve().parents[1] / "start.sh"
        self.assertTrue(script.exists(), "Startup guard must exist before deploying")
        with tempfile.TemporaryDirectory(prefix="tp-start-check-") as d:
            p = Path(d)
            shutil.copy2(script, p / script.name)
            r = subprocess.run(
                ["bash", str(p / script.name)], capture_output=True, text=True
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("existing database", r.stderr)
            self.assertFalse((p / "db/db.sqlite3").exists())

    def test_present_database_is_retained_and_start_does_not_run_migrations(self):
        script = Path(__file__).resolve().parents[1] / "start.sh"
        self.assertTrue(script.exists(), "Startup guard must exist before deploying")
        with tempfile.TemporaryDirectory(prefix="tp-start-check-") as d:
            p = Path(d)
            shutil.copy2(script, p / script.name)
            (p / "db").mkdir()
            db = p / "db/db.sqlite3"
            with sqlite3.connect(db) as c:
                c.execute("CREATE TABLE retained(id INTEGER)")
            before = db.read_bytes()
            (p / "bin").mkdir(parents=True)
            fake = p / "bin/python"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            fake.chmod(0o700)
            r = subprocess.run(
                ["bash", str(p / script.name)],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": str(p / "bin") + os.pathsep + os.environ["PATH"],
                },
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("gunicorn", r.stdout)
            self.assertNotIn("migrate", r.stdout)
            self.assertEqual(db.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
