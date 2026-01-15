"""Terraform inventory module.

Parses Terraform HCL files to extract resources, providers, and modules.
Uses python-hcl2 for HCL parsing.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import hcl2

from shared.constants import EXCLUDED_DIRS
from shared.schemas import (
    ModuleInfo,
    ProviderInfo,
    ResourceSummary,
    ResourceTypeSummary,
    TerraformInventory,
)


def parse_tf_file(file_path: Path) -> dict[str, Any] | None:
    """Parse a single Terraform file.

    Args:
        file_path: Path to .tf file

    Returns:
        Parsed HCL dict or None if parsing failed
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return hcl2.load(f)
    except Exception:
        # Silently skip files that can't be parsed
        # terraform validate will catch actual syntax errors
        return None


def extract_providers(parsed: dict[str, Any], file_path: str) -> list[ProviderInfo]:
    """Extract provider information from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path for context

    Returns:
        List of ProviderInfo objects
    """
    providers: list[ProviderInfo] = []

    # Check terraform.required_providers block
    terraform_blocks = parsed.get("terraform", [])
    for tf_block in terraform_blocks:
        if isinstance(tf_block, dict):
            required_providers = tf_block.get("required_providers", [])
            for rp in required_providers:
                if isinstance(rp, dict):
                    for name, config in rp.items():
                        if isinstance(config, dict):
                            providers.append(
                                ProviderInfo(
                                    name=name,
                                    source=config.get("source"),
                                    version_constraint=config.get("version"),
                                )
                            )
                        else:
                            # Simple string version constraint
                            providers.append(
                                ProviderInfo(
                                    name=name,
                                    source=None,
                                    version_constraint=str(config) if config else None,
                                )
                            )

    # Also check top-level provider blocks
    provider_blocks = parsed.get("provider", [])
    for provider in provider_blocks:
        if isinstance(provider, dict):
            for name, config in provider.items():
                # Only add if not already found in required_providers
                if not any(p.name == name for p in providers):
                    version = None
                    if isinstance(config, dict):
                        version = config.get("version")
                    providers.append(
                        ProviderInfo(
                            name=name,
                            source=None,
                            version_constraint=version,
                        )
                    )

    return providers


def extract_modules(parsed: dict[str, Any], file_path: str) -> list[ModuleInfo]:
    """Extract module information from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of ModuleInfo objects
    """
    modules: list[ModuleInfo] = []

    module_blocks = parsed.get("module", [])
    for module in module_blocks:
        if isinstance(module, dict):
            for name, config in module.items():
                if isinstance(config, dict):
                    source = config.get("source", "")
                    version = config.get("version")
                    modules.append(
                        ModuleInfo(
                            name=name,
                            source=source,
                            version=version,
                            declared_in=file_path,
                        )
                    )

    return modules


def extract_resources(
    parsed: dict[str, Any], file_path: str
) -> dict[str, list[str]]:
    """Extract resource information from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        Dict mapping resource type to list of file paths where declared
    """
    resources: dict[str, list[str]] = {}

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if isinstance(resource, dict):
            for resource_type, instances in resource.items():
                if resource_type not in resources:
                    resources[resource_type] = []
                # Each instance is a named resource
                if isinstance(instances, dict):
                    count = len(instances)
                else:
                    count = 1
                # Add file path for each instance
                for _ in range(count):
                    if file_path not in resources[resource_type]:
                        resources[resource_type].append(file_path)

    return resources


def generate_inventory(
    root_path: str | Path = ".",
    tf_paths: list[str] | None = None,
) -> TerraformInventory:
    """Generate Terraform inventory by parsing all .tf files.

    Args:
        root_path: Root directory of the repository
        tf_paths: Optional list of specific paths to scan

    Returns:
        TerraformInventory with aggregated information
    """
    root = Path(root_path).resolve()

    all_providers: list[ProviderInfo] = []
    all_modules: list[ModuleInfo] = []
    resource_map: dict[str, list[str]] = {}
    files_analyzed: list[str] = []
    terraform_paths: set[str] = set()

    # Determine paths to scan
    if tf_paths:
        scan_paths = [root / p for p in tf_paths]
    else:
        scan_paths = [root]

    for scan_path in scan_paths:
        if not scan_path.exists():
            continue

        for dirpath, dirnames, filenames in os.walk(scan_path):
            # Filter excluded directories
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]

            current_dir = Path(dirpath)

            for filename in filenames:
                if not filename.endswith(".tf"):
                    continue

                file_path = current_dir / filename
                rel_path = str(file_path.relative_to(root))
                files_analyzed.append(rel_path)

                # Track terraform path
                rel_dir = str(current_dir.relative_to(root))
                terraform_paths.add(rel_dir if rel_dir != "." else ".")

                # Parse file
                parsed = parse_tf_file(file_path)
                if parsed is None:
                    continue

                # Extract providers (deduplicate later)
                providers = extract_providers(parsed, rel_path)
                all_providers.extend(providers)

                # Extract modules
                modules = extract_modules(parsed, rel_path)
                all_modules.extend(modules)

                # Extract resources
                resources = extract_resources(parsed, rel_path)
                for resource_type, files in resources.items():
                    if resource_type not in resource_map:
                        resource_map[resource_type] = []
                    for f in files:
                        if f not in resource_map[resource_type]:
                            resource_map[resource_type].append(f)

    # Deduplicate providers by name (keep first occurrence)
    seen_providers: set[str] = set()
    unique_providers: list[ProviderInfo] = []
    for p in all_providers:
        if p.name not in seen_providers:
            seen_providers.add(p.name)
            unique_providers.append(p)

    # Build resource summary
    by_type: dict[str, ResourceTypeSummary] = {}
    total_count = 0
    for resource_type, files in resource_map.items():
        count = len(files)
        total_count += count
        by_type[resource_type] = ResourceTypeSummary(count=count, files=sorted(set(files)))

    resources = ResourceSummary(total_count=total_count, by_type=by_type)

    return TerraformInventory(
        generated_at=datetime.now(timezone.utc).isoformat(),
        terraform_paths=sorted(terraform_paths),
        resources=resources,
        providers=unique_providers,
        modules=all_modules,
        files_analyzed=sorted(files_analyzed),
    )


if __name__ == "__main__":
    # Quick test
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = generate_inventory(path)
    print(json.dumps(result.model_dump(), indent=2))
