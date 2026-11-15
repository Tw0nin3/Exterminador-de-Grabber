import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scanner import scan, quarantine, restore

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "Discord"
        self.core = self.root / "app-1" / "modules" / "discord_desktop_core-1" / "discord_desktop_core"
        self.core.mkdir(parents=True)
    def tearDown(self): self.temp.cleanup()
    def test_scan_and_restore(self):
        file = self.core / "index.js"
        data = b"localStorage.getItem('token'); 'discord.com/api/webhooks/1/x'"
        file.write_bytes(data)
        result = scan([self.root])
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.findings[0].risk, "ALTO")
        meta = quarantine(result.findings[0], Path(self.temp.name) / "quarantine")
        self.assertFalse(file.exists())
        self.assertEqual(restore(meta), file)
        self.assertEqual(file.read_bytes(), data)
        with self.assertRaises(FileExistsError): restore(meta)
    def test_changed_file_is_not_removed(self):
        file = self.core / "index.js"; file.write_text("stealToken")
        finding = scan([self.root]).findings[0]
        file.write_text("changed")
        with self.assertRaises(ValueError): quarantine(finding, Path(self.temp.name) / "q")
        self.assertEqual(file.read_text(), "changed")
    def test_clean_and_missing(self):
        (self.core / "index.js").write_text("module.exports = require('./core.asar');")
        result = scan([self.root, self.root / "missing"])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(len(result.errors), 1)
    def test_cancel_and_oversize(self):
        (self.core / "a.js").write_bytes(b"x" * (10 * 1024 * 1024 + 1))
        result = scan([self.root])
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(len(result.errors), 1)
        self.assertTrue(scan([self.root], lambda: True).cancelled)
    def test_tampered_backup(self):
        file = self.core / "index.js"; file.write_text("stealToken")
        meta = quarantine(scan([self.root]).findings[0], Path(self.temp.name) / "q")
        info = json.loads(meta.read_text(encoding="utf-8"))
        (meta.parent / info["backup"]).write_bytes(b"tampered")
        with self.assertRaises(ValueError): restore(meta)
        self.assertFalse(file.exists())

if __name__ == "__main__": unittest.main()
