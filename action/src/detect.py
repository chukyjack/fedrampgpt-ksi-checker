"""Terraform detection module.

Scans repository for Terraform files and produces terraform_detection.json.
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from shared.constants import EXCLUDED_DIRS, TF_FILE_PATTERN, TF_LOCKFILE_NAME
from shared.schemas import TerraformDetection


def scan_for_terraform(root_path: str | Path = ".") -> TerraformDetection:
    """Scan a directory tree for Terraform files.

    Args:
        root_path: Root directory to scan (default: current directory)

    Returns:
        TerraformDetection with scan results
    """
    root = Path(root_path).resolve()
    tf_files: list[Path] = []
    tf_dirs: set[str] = set()
    lockfile_found = False

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out excluded directories (modifies dirnames in-place)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]

        current_dir = Path(dirpath)
        rel_dir = current_dir.relative_to(root)

        for filename in filenames:
            # Check for .tf files
            if filename.endswith(".tf"):
                tf_files.append(current_dir / filename)
                # Store relative path of directory, or "." for root
                dir_str = str(rel_dir) if str(rel_dir) != "." else "."
                tf_dirs.add(dir_str)

            # Check for lockfile
            if filename == TF_LOCKFILE_NAME:
                lockfile_found = True

    # Convert tf_files to relative paths for output
    tf_file_paths = [str(f.relative_to(root)) for f in sorted(tf_files)]

    return TerraformDetection(
        detected=len(tf_files) > 0,
        tf_file_count=len(tf_files),
        tf_paths=sorted(tf_dirs),
        lockfile_present=lockfile_found,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


def get_tf_root_paths(detection: TerraformDetection) -> list[str]:
    """Get the root paths that should be used for terraform init/validate.

    For MVP, we use the first directory containing .tf files.
    In the future, this could support multiple roots.

    Args:
        detection: TerraformDetection result

    Returns:
        List of paths to run terraform commands in
    """
    if not detection.detected:
        return []

    # For MVP, use the first path (often "." for root)
    # Could be expanded to handle monorepos with multiple TF roots
    return detection.tf_paths[:1] if detection.tf_paths else ["."]


if __name__ == "__main__":
    # Quick test
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = scan_for_terraform(path)
    print(json.dumps(result.model_dump(), indent=2))
