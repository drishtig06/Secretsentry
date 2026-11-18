import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secretsentry.cli import main
from secretsentry.scanner import scan


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_detects_common_secret_patterns_and_redacts_values(self) -> None:
        target = self.root / "config.py"
        target.write_text(
            "aws = '" + "AKIA12345678" + "90ABCDEF'\n"
            + "token = 'ghp_" + "abcdefghijklmnopqrstuvwxyz123456'\n"
            + "pass" + "word = 'SuperSecretValue123'\n"
            + "-----BEGIN " + "PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        findings = scan(self.root)

        self.assertEqual(
            {"aws-access-key", "github-token", "credential-assignment", "private-key"},
            {finding.rule_id for finding in findings},
        )
        self.assertTrue(
            all("SuperSecretValue123" not in finding.redacted_match for finding in findings)
        )

    def test_skips_default_excluded_directories_and_large_files(self) -> None:
        ignored = self.root / ".git" / "config"
        ignored.parent.mkdir()
        ignored.write_text("token = 'dontshowthisvalue'", encoding="utf-8")
        big_file = self.root / "large.env"
        big_file.write_text("token = 'dontshowthisvalue'", encoding="utf-8")

        self.assertEqual([], scan(self.root, max_file_size=10))

    def test_reports_relative_path_and_line_number(self) -> None:
        (self.root / "app.env").write_text(
            "safe=true\napi_key=abcdefghijk12345", encoding="utf-8"
        )

        findings = scan(self.root)

        self.assertEqual(("app.env", 2), (findings[0].path, findings[0].line))

    def test_cli_json_output_never_contains_full_detected_value(self) -> None:
        (self.root / "app.env").write_text("password='dontprintthissecret'", encoding="utf-8")
        output = self.root / "report.json"

        with patch("builtins.print") as print_mock:
            result = main([str(self.root), "--json", "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(1, result)
        self.assertNotIn("dontprintthissecret", output.read_text(encoding="utf-8"))
        self.assertEqual("app.env", report[0]["path"])
        self.assertTrue(print_mock.called)

    def test_clean_scan_returns_zero(self) -> None:
        (self.root / "safe.txt").write_text("nothing sensitive here", encoding="utf-8")

        with patch("builtins.print"):
            self.assertEqual(0, main([str(self.root)]))


if __name__ == "__main__":
    unittest.main()
