"""Tests for Terraform detection module."""

import os
import tempfile
from pathlib import Path

import pytest

from action.src.detect import get_tf_root_paths, scan_for_terraform


class TestScanForTerraform:
    """Tests for scan_for_terraform function."""

    def test_detects_terraform_files(self):
        """Should detect .tf files in directory."""
        fixtures_path = Path(__file__).parent / "fixtures" / "pass-repo"
        result = scan_for_terraform(fixtures_path)

        assert result.detected is True
        assert result.tf_file_count >= 2  # main.tf and variables.tf
        assert "." in result.tf_paths

    def test_empty_directory(self):
        """Should return detected=False for empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scan_for_terraform(tmpdir)

            assert result.detected is False
            assert result.tf_file_count == 0
            assert result.tf_paths == []

    def test_excludes_terraform_directory(self):
        """Should exclude .terraform directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .terraform directory with .tf files
            terraform_dir = Path(tmpdir) / ".terraform"
            terraform_dir.mkdir()
            (terraform_dir / "providers.tf").write_text("# provider cache")

            # Create a valid .tf file in root
            (Path(tmpdir) / "main.tf").write_text("# main config")

            result = scan_for_terraform(tmpdir)

            assert result.detected is True
            assert result.tf_file_count == 1
            assert ".terraform" not in str(result.tf_paths)

    def test_detects_lockfile(self):
        """Should detect .terraform.lock.hcl."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "main.tf").write_text("# config")
            (Path(tmpdir) / ".terraform.lock.hcl").write_text("# lockfile")

            result = scan_for_terraform(tmpdir)

            assert result.lockfile_present is True

    def test_no_lockfile(self):
        """Should report lockfile_present=False when no lockfile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "main.tf").write_text("# config")

            result = scan_for_terraform(tmpdir)

            assert result.lockfile_present is False

    def test_nested_terraform_files(self):
        """Should find .tf files in subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            subdir = Path(tmpdir) / "modules" / "vpc"
            subdir.mkdir(parents=True)
            (subdir / "main.tf").write_text("# vpc module")
            (Path(tmpdir) / "main.tf").write_text("# root config")

            result = scan_for_terraform(tmpdir)

            assert result.detected is True
            assert result.tf_file_count == 2
            assert "." in result.tf_paths
            assert "modules/vpc" in result.tf_paths


class TestGetTfRootPaths:
    """Tests for get_tf_root_paths function."""

    def test_returns_paths_when_detected(self):
        """Should return tf_paths when Terraform is detected."""
        fixtures_path = Path(__file__).parent / "fixtures" / "pass-repo"
        detection = scan_for_terraform(fixtures_path)

        paths = get_tf_root_paths(detection)

        assert len(paths) > 0
        assert paths[0] == "."

    def test_returns_empty_when_not_detected(self):
        """Should return empty list when no Terraform detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            detection = scan_for_terraform(tmpdir)
            paths = get_tf_root_paths(detection)

            assert paths == []
