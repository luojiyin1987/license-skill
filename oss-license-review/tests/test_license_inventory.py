import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_module():
    module_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "license_inventory.py"
    )
    spec = importlib.util.spec_from_file_location("license_inventory", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


li = load_module()


class LicenseInventoryTests(unittest.TestCase):
    def test_split_spdx_expression(self):
        tokens = li.split_license_expression("MIT OR Apache-2.0")
        self.assertEqual(set(tokens), {"MIT", "APACHE-2.0"})

    def test_guess_mit_from_text_pattern(self):
        text = (
            "Permission is hereby granted, free of charge, to any person obtaining a copy "
            "of this software and associated documentation files..."
        )
        self.assertEqual(li.guess_license_from_text(text), "MIT")

    def test_agpl_saas_high_risk_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text(
                "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n",
                encoding="utf-8",
            )
            report = li.build_report(repo, use_case="saas", modified=True)
            self.assertEqual(report["risk_level"], "high")
            self.assertIn("AGPL", report["high_copyleft_alerts"])
            reasons = " ".join(report["risk_reasons"])
            self.assertIn("SaaS mode", reasons)

    def test_spdx_expression_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text(
                "SPDX-License-Identifier: MIT OR Apache-2.0\n",
                encoding="utf-8",
            )
            report = li.build_report(repo, use_case="binary", modified=False)
            self.assertIn("MIT OR Apache-2.0", report["spdx_expressions"])
            self.assertTrue(report["spdx_expression_evaluations"][0]["valid"])
            self.assertEqual(report["spdx_expression_evaluations"][0]["min_risk"], "low")
            self.assertEqual(report["spdx_expression_evaluations"][0]["max_risk"], "low")
            self.assertTrue(
                any(
                    "Composite SPDX expressions" in note
                    for note in report["restrictions_and_conflicts"]
                )
            )

    def test_spdx_expression_with_exception_is_evaluated(self):
        result = li.evaluate_spdx_expression(
            "GPL-2.0-only WITH Classpath-exception-2.0 OR MIT"
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["branch_count"], 2)
        self.assertEqual(result["min_risk"], "low")
        self.assertEqual(result["max_risk"], "medium")
        self.assertIn("CLASSPATH-EXCEPTION-2.0", result["exceptions"])
        self.assertIn(
            "Known GPL linking exception reduces copyleft risk for this branch.",
            result["exception_impacts"],
        )
        self.assertIn("CLASSPATH-EXCEPTION-2.0", result["applicable_exceptions"])
        self.assertNotIn("GPL-2.0-ONLY", result["high_risk_tokens"])

    def test_spdx_exception_version_incompatibility_warning(self):
        result = li.evaluate_spdx_expression("GPL-3.0-only WITH Bootloader-exception")
        self.assertTrue(result["valid"])
        self.assertEqual(result["min_risk"], "high")
        self.assertEqual(result["max_risk"], "high")
        self.assertTrue(result["exception_compatibility_warnings"])
        self.assertEqual(result["applicable_exceptions"], [])

    def test_spdx_exception_mapping_bootloader_compatible_with_gpl2(self):
        result = li.evaluate_spdx_expression("GPL-2.0-only WITH Bootloader-exception")
        self.assertTrue(result["valid"])
        self.assertEqual(result["min_risk"], "medium")
        self.assertEqual(result["max_risk"], "medium")
        self.assertIn("BOOTLOADER-EXCEPTION", result["applicable_exceptions"])

    def test_spdx_branch_explosion_is_truncated(self):
        parts = [f"(LIC{i}A OR LIC{i}B)" for i in range(8)]
        expr = " AND ".join(parts)  # 2^8 unique branches > MAX_SPDX_BRANCHES
        result = li.evaluate_spdx_expression(expr)
        self.assertTrue(result["valid"])
        self.assertTrue(result["branches_truncated"])

    def test_spdx_nesting_depth_limit(self):
        expr = "(" * 40 + "MIT" + ")" * 40
        result = li.evaluate_spdx_expression(expr)
        self.assertFalse(result["valid"])
        self.assertIn("nesting too deep", result["error"])

    def test_parse_cyclonedx_sbom_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text("MIT License\n", encoding="utf-8")
            sbom = {
                "components": [
                    {"name": "a", "licenses": [{"license": {"id": "Apache-2.0"}}]},
                    {"name": "b", "licenses": [{"expression": "MIT OR GPL-3.0-only"}]},
                ]
            }
            (repo / "sbom.json").write_text(json.dumps(sbom), encoding="utf-8")
            report = li.build_report(repo, use_case="binary", modified=False)
            manifest_types = {item["type"] for item in report["manifest_declarations"]}
            self.assertIn("sbom.json", manifest_types)
            self.assertIn("GPL-3.0-ONLY", report["high_copyleft_alerts"])

    def test_parse_cyclonedx_15_plus_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "LICENSE").write_text("MIT License\n", encoding="utf-8")
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {
                        "licenses": [{"expression": "MPL-2.0 OR MIT"}]
                    }
                },
                "components": [
                    {
                        "name": "core",
                        "evidence": {"licenses": [{"license": {"id": "Apache-2.0"}}]},
                    }
                ],
                "services": [
                    {"name": "api", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]}
                ],
            }
            (repo / "deps.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
            report = li.build_report(repo, use_case="saas", modified=False)
            sbom_entries = [
                item for item in report["manifest_declarations"] if item["type"] == "sbom.json"
            ]
            self.assertTrue(sbom_entries)
            declared = sbom_entries[0]["declared"]
            self.assertEqual(declared["bom_format"], "CycloneDX")
            self.assertEqual(declared["spec_version"], "1.5")
            self.assertIn(declared["parse_mode"], {"full", "stream"})
            self.assertIn("AGPL-3.0-ONLY", report["high_copyleft_alerts"])

    def test_streaming_path_matcher_is_expanded(self):
        self.assertTrue(
            li.should_collect_streaming_string(
                "metadata.component.evidence.licenses.item.license.id"
            )
        )
        self.assertTrue(
            li.should_collect_streaming_string("components.item.licenses.item.expression")
        )
        self.assertFalse(li.should_collect_streaming_string("components.item.name"))

    def test_streaming_failure_falls_back_to_full_parse(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"licenses": [{"expression": "MIT OR Apache-2.0"}]}],
            }
            sbom_path = repo / "sbom.json"
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

            original_ijson = li.ijson
            original_threshold = li.SBOM_STREAMING_THRESHOLD_BYTES
            original_stream_fn = li.parse_sbom_json_streaming
            try:
                li.ijson = object()
                li.SBOM_STREAMING_THRESHOLD_BYTES = 1
                li.parse_sbom_json_streaming = lambda _: {}
                declared = li.parse_sbom_json(sbom_path)
            finally:
                li.ijson = original_ijson
                li.SBOM_STREAMING_THRESHOLD_BYTES = original_threshold
                li.parse_sbom_json_streaming = original_stream_fn

            self.assertEqual(declared["parse_mode"], "full")
            self.assertEqual(declared["bom_format"], "CycloneDX")

    def test_package_lock_license_hints_affect_risk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            package_lock = {
                "packages": {
                    "": {"license": "MIT"},
                    "node_modules/copyleft-lib": {"license": "GPL-3.0-only"},
                }
            }
            (repo / "package-lock.json").write_text(
                json.dumps(package_lock), encoding="utf-8"
            )

            report = li.build_report(repo, use_case="binary", modified=False)

            manifest_types = {item["type"] for item in report["manifest_declarations"]}
            self.assertIn("package-lock.json", manifest_types)
            declared = report["manifest_declarations"][0]["declared"]
            self.assertIn("GPL-3.0-only", declared["dependency_license_values"])
            self.assertEqual(report["risk_level"], "high")
            self.assertIn("GPL-3.0-ONLY", report["high_copyleft_alerts"])

    def test_unlicensed_marker_blocks_reuse_guidance(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "package.json").write_text(
                json.dumps({"license": "UNLICENSED"}), encoding="utf-8"
            )

            report = li.build_report(repo, use_case="binary", modified=False)

            self.assertEqual(report["risk_level"], "high")
            self.assertTrue(
                any("no-license-grant marker" in reason for reason in report["risk_reasons"])
            )
            self.assertEqual(
                report["required_actions"],
                [
                    "Do not reuse code until a valid license grant is confirmed.",
                    "Ask maintainers for explicit license terms or written permission.",
                ],
            )
            self.assertTrue(
                any(
                    "usage rights as withheld" in note
                    for note in report["restrictions_and_conflicts"]
                )
            )

    def test_pom_license_name_is_normalized_to_spdx(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "pom.xml").write_text(
                """
                <project>
                  <licenses>
                    <license>
                      <name>The Apache Software License, Version 2.0</name>
                      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
                    </license>
                  </licenses>
                </project>
                """,
                encoding="utf-8",
            )

            report = li.build_report(repo, use_case="binary", modified=False)

            declared = report["manifest_declarations"][0]["declared"]
            self.assertIn("APACHE-2.0", declared["licenses"])
            self.assertEqual(report["risk_level"], "low")
            self.assertTrue(
                any("NOTICE handling" in note for note in report["restrictions_and_conflicts"])
            )

    def test_primary_license_guess_falls_back_to_project_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "package.json").write_text(
                json.dumps({"license": "MIT"}), encoding="utf-8"
            )

            report = li.build_report(repo, use_case="binary", modified=False)

            self.assertEqual(report["primary_license_guess"], "MIT")


if __name__ == "__main__":
    unittest.main()
