"""Regression checks for cases that could silently under-report findings."""

import argparse
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import patchroute as scanner


class CoverageTests(unittest.TestCase):
    def args(self, inventory, report):
        return argparse.Namespace(
            quiet=True, ecosystem="generic", demo=False, host=False,
            input=[str(inventory)], no_recurse=False, nvd_key=None,
            ignore=None, json=None, output=str(report), md=None,
            fail_on="any",
        )

    def test_feed_failure_cannot_pass_ci(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            report = Path(tmp) / "report.html"
            inventory.write_text(json.dumps({"packages": [
                {"name": "requests", "version": "2.0", "ecosystem": "PyPI"}
            ]}), encoding="utf-8")
            with patch.object(scanner, "_post_json",
                              side_effect=urllib.error.URLError("offline")), \
                 patch.object(scanner, "load_kev", return_value={}):
                exit_code = scanner.run(self.args(inventory, report))
            self.assertEqual(exit_code, 3)
            self.assertIn("INCOMPLETE SCAN", report.read_text(encoding="utf-8"))

    def test_unpinned_requirements_cannot_masquerade_as_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "requirements.txt"
            report = Path(tmp) / "report.html"
            inventory.write_text("django==2.2.0\nrequests>=2.0\n", encoding="utf-8")
            with patch.object(scanner, "_post_json", return_value={"results": [{"vulns": []}]}), \
                 patch.object(scanner, "load_kev", return_value={}):
                exit_code = scanner.run(self.args(inventory, report))
            self.assertEqual(exit_code, 3)
            self.assertIn("un-pinned requirement", report.read_text(encoding="utf-8"))


class FindingIntegrityTests(unittest.TestCase):
    def test_affected_match_survives_older_fix_on_another_branch(self):
        finding = scanner.Finding(
            "CVE-2026-0001", scanner.Package("example", "2.0", "PyPI"),
            fixed_versions=["1.5"], cvss_score=8.0, cvss_severity="HIGH",
        )
        scanner.check_false_positives([finding])
        scanner.score_findings([finding])
        self.assertEqual(finding.confidence, 1.0)
        self.assertEqual(scanner._exit_code([finding], "high", quiet=True), 2)

    def test_conflicting_fixes_do_not_claim_one_package_upgrade(self):
        package = scanner.Package("example", "1.0", "PyPI")
        findings = [
            scanner.Finding("CVE-2026-0001", package, fixed_versions=["1.2"]),
            scanner.Finding("CVE-2026-0002", package, fixed_versions=["2.0"]),
        ]
        scanner.score_findings(findings)
        scanner.build(findings)
        self.assertEqual(scanner.plan(findings)[0]["target"], "")

    def test_untrusted_advisory_url_is_not_clickable(self):
        finding = scanner.Finding(
            "CVE-2026-0001", scanner.Package("example", "1.0", "PyPI"),
            references=["javascript:alert(1)", "https://example.org/advisory"],
        )
        links = scanner._refs(finding)
        self.assertNotIn("javascript:", links)
        self.assertIn('href="https://example.org/advisory"', links)


if __name__ == "__main__":
    unittest.main()
