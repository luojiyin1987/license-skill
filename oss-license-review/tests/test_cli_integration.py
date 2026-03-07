import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "license_inventory.py"
)


class LicenseInventoryCliIntegrationTests(unittest.TestCase):
    def test_cli_human_output_includes_exception_semantics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text(
                "SPDX-License-Identifier: MIT OR GPL-2.0-only WITH Classpath-exception-2.0\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), str(repo), "--use-case", "binary"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("SPDX expression evaluations:", proc.stdout)
            self.assertIn("WITH exceptions: CLASSPATH-EXCEPTION-2.0", proc.stdout)
            self.assertIn("risk=low..medium", proc.stdout)

    def test_cli_human_output_exception_incompatibility_warning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text(
                "SPDX-License-Identifier: GPL-3.0-only WITH Bootloader-exception\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), str(repo)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("may be incompatible with GPL tokens", proc.stdout)

    def test_cli_json_output_cyclonedx_15(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text("MIT License\n", encoding="utf-8")
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"name": "core", "licenses": [{"expression": "MIT OR Apache-2.0"}]}
                ],
                "services": [
                    {"name": "api", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]}
                ],
            }
            (repo / "deps.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    str(repo),
                    "--use-case",
                    "saas",
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["risk_level"], "high")
            self.assertIn("AGPL-3.0-ONLY", data["high_copyleft_alerts"])
            self.assertTrue(data["spdx_expression_evaluations"])

    def test_cli_json_reports_spdx_truncation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            parts = [f"(LIC{i}A OR LIC{i}B)" for i in range(8)]
            expr = " AND ".join(parts)
            (repo / "LICENSE").write_text(
                f"SPDX-License-Identifier: {expr}\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), str(repo), "--json"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertTrue(data["spdx_expression_evaluations"][0]["branches_truncated"])


if __name__ == "__main__":
    unittest.main()
