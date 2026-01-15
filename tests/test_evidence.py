"""Tests for evidence pack generation module."""

import json
import tempfile
import zipfile
from pathlib import Path

import pytest

from action.src.detect import scan_for_terraform
from action.src.evidence import EvidencePackBuilder, build_evidence_pack
from action.src.inventory import generate_inventory
from shared.schemas import CriterionStatus, KSIStatus, TerraformDetection


class TestEvidencePackBuilder:
    """Tests for EvidencePackBuilder class."""

    def test_setup_directories(self):
        """Should create evidence directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)
            builder.setup_directories()

            assert (Path(tmpdir) / "evidence" / "ksi-mla-05").exists()
            assert (Path(tmpdir) / "evidence" / "ksi-mla-05" / "declared").exists()

    def test_write_json_file(self):
        """Should write JSON file to evidence pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)
            builder.setup_directories()

            data = {"test": "data", "number": 42}
            path = builder.write_json_file("test.json", data, "Test file")

            assert path.exists()
            with open(path) as f:
                loaded = json.load(f)
            assert loaded == data
            assert ("evidence/ksi-mla-05/test.json", "Test file") in builder.files_written

    def test_compute_criteria_pass(self):
        """Should compute PASS criteria correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)

            # Mock detection result
            detection = TerraformDetection(
                detected=True,
                tf_file_count=5,
                tf_paths=["."],
                lockfile_present=True,
                scanned_at="2024-01-01T00:00:00Z",
            )

            # Mock eval result (success)
            class MockEvalResult:
                success = True
                terraform_version = "1.6.0"
                error_message = None

            criteria = builder.compute_criteria(
                detection=detection,
                eval_result=MockEvalResult(),
                trigger_event="schedule",
                evidence_generated=True,
            )

            assert len(criteria) == 4

            # All should be PASS
            statuses = {c.id: c.status for c in criteria}
            assert statuses["MLA05-A"] == CriterionStatus.PASS
            assert statuses["MLA05-B"] == CriterionStatus.PASS
            assert statuses["MLA05-C"] == CriterionStatus.PASS
            assert statuses["MLA05-D"] == CriterionStatus.PASS

    def test_compute_criteria_fail_no_schedule(self):
        """Should FAIL MLA05-C when not triggered by schedule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)

            detection = TerraformDetection(
                detected=True,
                tf_file_count=5,
                tf_paths=["."],
                lockfile_present=True,
                scanned_at="2024-01-01T00:00:00Z",
            )

            class MockEvalResult:
                success = True
                terraform_version = "1.6.0"
                error_message = None

            criteria = builder.compute_criteria(
                detection=detection,
                eval_result=MockEvalResult(),
                trigger_event="push",  # Not schedule
                evidence_generated=True,
            )

            statuses = {c.id: c.status for c in criteria}
            assert statuses["MLA05-C"] == CriterionStatus.FAIL

    def test_compute_criteria_fail_no_terraform(self):
        """Should FAIL MLA05-A when no Terraform detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)

            detection = TerraformDetection(
                detected=False,
                tf_file_count=0,
                tf_paths=[],
                lockfile_present=False,
                scanned_at="2024-01-01T00:00:00Z",
            )

            criteria = builder.compute_criteria(
                detection=detection,
                eval_result=None,
                trigger_event="schedule",
                evidence_generated=True,
            )

            statuses = {c.id: c.status for c in criteria}
            assert statuses["MLA05-A"] == CriterionStatus.FAIL
            assert statuses["MLA05-B"] == CriterionStatus.SKIP

    def test_compute_overall_status(self):
        """Should compute overall status from criteria."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = EvidencePackBuilder(tmpdir)

            # All PASS
            from shared.schemas import CriterionResult

            all_pass = [
                CriterionResult(id="A", name="A", status=CriterionStatus.PASS, reason="ok"),
                CriterionResult(id="B", name="B", status=CriterionStatus.PASS, reason="ok"),
            ]
            status, reasons = builder.compute_overall_status(all_pass)
            assert status == KSIStatus.PASS

            # One FAIL
            one_fail = [
                CriterionResult(id="A", name="A", status=CriterionStatus.PASS, reason="ok"),
                CriterionResult(id="B", name="B", status=CriterionStatus.FAIL, reason="failed"),
            ]
            status, reasons = builder.compute_overall_status(one_fail)
            assert status == KSIStatus.FAIL

            # One ERROR
            one_error = [
                CriterionResult(id="A", name="A", status=CriterionStatus.PASS, reason="ok"),
                CriterionResult(id="B", name="B", status=CriterionStatus.ERROR, reason="error"),
            ]
            status, reasons = builder.compute_overall_status(one_error)
            assert status == KSIStatus.ERROR


class TestBuildEvidencePack:
    """Tests for build_evidence_pack function."""

    def test_builds_complete_evidence_pack(self):
        """Should build complete evidence pack with all required files."""
        fixtures_path = Path(__file__).parent / "fixtures" / "pass-repo"
        detection = scan_for_terraform(fixtures_path)
        inventory = generate_inventory(fixtures_path, detection.tf_paths)

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path, artifact_name, status = build_evidence_pack(
                output_dir=tmpdir,
                detection=detection,
                inventory=inventory,
                eval_result=None,  # Skip actual terraform eval in tests
                repository="test/repo",
                commit_sha="abc1234567890",
                workflow_name="Test Workflow",
                workflow_run_id="12345",
                workflow_run_url="https://github.com/test/repo/actions/runs/12345",
                trigger_event="schedule",
                actor="test-user",
                terraform_version="1.6.0",
            )

            # Check zip was created
            assert zip_path.exists()
            assert artifact_name.startswith("evidence_ksi-mla-05_")

            # Check zip contents
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()

                # Required files
                assert any("collected_at.json" in n for n in names)
                assert any("scope.json" in n for n in names)
                assert any("tools.json" in n for n in names)
                assert any("terraform_detection.json" in n for n in names)
                assert any("terraform_inventory.json" in n for n in names)
                assert any("evaluation_manifest.json" in n for n in names)
                assert any("manifest.json" in n for n in names)
                assert any("hashes.sha256" in n for n in names)

            # Check results.json was created
            results_path = Path(tmpdir) / "results.json"
            assert results_path.exists()
            with open(results_path) as f:
                results = json.load(f)
            assert results["ksi_id"] == "KSI-MLA-05"
            assert results["status"] in ["PASS", "FAIL", "ERROR"]

    def test_evidence_pack_without_terraform(self):
        """Should generate evidence pack even without Terraform."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_dir = Path(tmpdir) / "empty"
            empty_dir.mkdir()

            detection = scan_for_terraform(empty_dir)

            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir()

            zip_path, artifact_name, status = build_evidence_pack(
                output_dir=output_dir,
                detection=detection,
                inventory=None,
                eval_result=None,
                repository="test/repo",
                commit_sha="abc1234567890",
                workflow_name="Test Workflow",
                workflow_run_id="12345",
                workflow_run_url="https://github.com/test/repo/actions/runs/12345",
                trigger_event="schedule",
                actor="test-user",
            )

            assert zip_path.exists()
            # Should be FAIL or ERROR due to no Terraform
            assert status in [KSIStatus.FAIL, KSIStatus.ERROR]
