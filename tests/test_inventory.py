"""Tests for Terraform inventory module."""

from pathlib import Path

import pytest

from action.src.inventory import (
    extract_modules,
    extract_providers,
    extract_resources,
    generate_inventory,
    parse_tf_file,
)


class TestParseTfFile:
    """Tests for parse_tf_file function."""

    def test_parses_valid_tf_file(self):
        """Should parse a valid Terraform file."""
        fixtures_path = Path(__file__).parent / "fixtures" / "pass-repo" / "main.tf"
        result = parse_tf_file(fixtures_path)

        assert result is not None
        assert "terraform" in result or "resource" in result

    def test_returns_none_for_invalid_file(self, tmp_path):
        """Should return None for invalid HCL."""
        invalid_file = tmp_path / "invalid.tf"
        invalid_file.write_text("this is { not valid { hcl }")

        result = parse_tf_file(invalid_file)

        # Should return None or empty dict, not raise
        assert result is None or result == {}

    def test_returns_none_for_missing_file(self, tmp_path):
        """Should return None for missing file."""
        missing_file = tmp_path / "missing.tf"

        result = parse_tf_file(missing_file)

        assert result is None


class TestExtractProviders:
    """Tests for extract_providers function."""

    def test_extracts_required_providers(self):
        """Should extract providers from required_providers block."""
        parsed = {
            "terraform": [
                {
                    "required_providers": [
                        {
                            "aws": {
                                "source": "hashicorp/aws",
                                "version": "~> 5.0",
                            }
                        }
                    ]
                }
            ]
        }

        providers = extract_providers(parsed, "main.tf")

        assert len(providers) == 1
        assert providers[0].name == "aws"
        assert providers[0].source == "hashicorp/aws"
        assert providers[0].version_constraint == "~> 5.0"

    def test_extracts_provider_blocks(self):
        """Should extract providers from provider blocks."""
        parsed = {
            "provider": [{"google": {"project": "my-project", "region": "us-central1"}}]
        }

        providers = extract_providers(parsed, "main.tf")

        assert len(providers) == 1
        assert providers[0].name == "google"


class TestExtractModules:
    """Tests for extract_modules function."""

    def test_extracts_modules(self):
        """Should extract module information."""
        parsed = {
            "module": [
                {
                    "vpc": {
                        "source": "terraform-aws-modules/vpc/aws",
                        "version": "5.1.0",
                    }
                }
            ]
        }

        modules = extract_modules(parsed, "main.tf")

        assert len(modules) == 1
        assert modules[0].name == "vpc"
        assert modules[0].source == "terraform-aws-modules/vpc/aws"
        assert modules[0].version == "5.1.0"
        assert modules[0].declared_in == "main.tf"


class TestExtractResources:
    """Tests for extract_resources function."""

    def test_extracts_resources(self):
        """Should extract resource types and files."""
        parsed = {
            "resource": [
                {"aws_instance": {"web": {"ami": "ami-123"}}},
                {"aws_instance": {"api": {"ami": "ami-456"}}},
                {"aws_s3_bucket": {"data": {"bucket": "my-bucket"}}},
            ]
        }

        resources = extract_resources(parsed, "main.tf")

        assert "aws_instance" in resources
        assert "aws_s3_bucket" in resources


class TestGenerateInventory:
    """Tests for generate_inventory function."""

    def test_generates_inventory_for_pass_repo(self):
        """Should generate complete inventory for pass-repo fixture."""
        fixtures_path = Path(__file__).parent / "fixtures" / "pass-repo"
        inventory = generate_inventory(fixtures_path)

        assert inventory.schema_version == "1.0"
        assert len(inventory.terraform_paths) > 0
        assert len(inventory.files_analyzed) >= 2

        # Should find providers
        provider_names = [p.name for p in inventory.providers]
        assert "aws" in provider_names

        # Should find modules
        module_names = [m.name for m in inventory.modules]
        assert "vpc" in module_names

        # Should find resources
        assert inventory.resources.total_count > 0
        assert "aws_instance" in inventory.resources.by_type
        assert "aws_s3_bucket" in inventory.resources.by_type

    def test_generates_inventory_for_empty_dir(self, tmp_path):
        """Should generate empty inventory for directory without .tf files."""
        inventory = generate_inventory(tmp_path)

        assert inventory.schema_version == "1.0"
        assert inventory.resources.total_count == 0
        assert len(inventory.providers) == 0
        assert len(inventory.modules) == 0
