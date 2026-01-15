"""Terraform evaluation module.

Runs terraform init and validate to perform machine-based evaluation.
"""

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TerraformEvalResult:
    """Result of terraform evaluation."""

    success: bool
    terraform_version: str | None
    init_success: bool
    init_output: str
    init_error: str
    validate_success: bool
    validate_output: str
    validate_error: str
    error_message: str | None = None


def get_terraform_version() -> str | None:
    """Get the installed Terraform version.

    Returns:
        Version string (e.g., "1.6.0") or None if Terraform not found
    """
    try:
        result = subprocess.run(
            ["terraform", "version", "-json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            import json

            version_info = json.loads(result.stdout)
            return version_info.get("terraform_version")
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass

    # Fallback to non-JSON version output
    try:
        result = subprocess.run(
            ["terraform", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            # Parse "Terraform v1.6.0" format
            first_line = result.stdout.strip().split("\n")[0]
            if first_line.startswith("Terraform v"):
                return first_line.replace("Terraform v", "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def run_terraform_init(working_dir: str | Path) -> tuple[bool, str, str]:
    """Run terraform init with backend disabled.

    Args:
        working_dir: Directory to run terraform init in

    Returns:
        Tuple of (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            ["terraform", "init", "-backend=false", "-no-color"],
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes timeout for init
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Terraform init timed out after 5 minutes"
    except FileNotFoundError:
        return False, "", "Terraform executable not found"
    except Exception as e:
        return False, "", f"Terraform init failed: {str(e)}"


def run_terraform_validate(working_dir: str | Path) -> tuple[bool, str, str]:
    """Run terraform validate.

    Args:
        working_dir: Directory to run terraform validate in

    Returns:
        Tuple of (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            ["terraform", "validate", "-no-color"],
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minutes timeout for validate
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Terraform validate timed out after 2 minutes"
    except FileNotFoundError:
        return False, "", "Terraform executable not found"
    except Exception as e:
        return False, "", f"Terraform validate failed: {str(e)}"


def evaluate_terraform(working_dir: str | Path = ".") -> TerraformEvalResult:
    """Run full Terraform evaluation (init + validate).

    Args:
        working_dir: Directory containing Terraform configuration

    Returns:
        TerraformEvalResult with evaluation results
    """
    working_dir = Path(working_dir).resolve()

    # Get Terraform version first
    terraform_version = get_terraform_version()
    if terraform_version is None:
        return TerraformEvalResult(
            success=False,
            terraform_version=None,
            init_success=False,
            init_output="",
            init_error="Terraform not installed or not in PATH",
            validate_success=False,
            validate_output="",
            validate_error="",
            error_message="Terraform executable not found. Ensure Terraform is installed.",
        )

    # Run terraform init
    init_success, init_output, init_error = run_terraform_init(working_dir)
    if not init_success:
        return TerraformEvalResult(
            success=False,
            terraform_version=terraform_version,
            init_success=False,
            init_output=init_output,
            init_error=init_error,
            validate_success=False,
            validate_output="",
            validate_error="Skipped due to init failure",
            error_message=f"Terraform init failed: {init_error or 'Unknown error'}",
        )

    # Run terraform validate
    validate_success, validate_output, validate_error = run_terraform_validate(working_dir)

    return TerraformEvalResult(
        success=validate_success,
        terraform_version=terraform_version,
        init_success=True,
        init_output=init_output,
        init_error=init_error,
        validate_success=validate_success,
        validate_output=validate_output,
        validate_error=validate_error,
        error_message=None if validate_success else f"Terraform validate failed: {validate_error}",
    )


if __name__ == "__main__":
    # Quick test
    import json

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = evaluate_terraform(path)
    print(f"Success: {result.success}")
    print(f"Terraform Version: {result.terraform_version}")
    print(f"Init Success: {result.init_success}")
    print(f"Validate Success: {result.validate_success}")
    if result.error_message:
        print(f"Error: {result.error_message}")
