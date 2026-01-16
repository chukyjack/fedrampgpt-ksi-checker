"""CNA-01 Evaluator: Restrict Network Traffic.

Evaluates Terraform configuration for compliance with KSI-CNA-01:
"Persistently ensure all machine-based information resources are configured
to limit inbound and outbound network traffic."
"""

from shared.constants_cna import CNA01_CRITERIA_DEFINITIONS
from shared.schemas_network import (
    CNA01CriterionResult,
    CNA01Finding,
    CNA01Summary,
    NetworkInventory,
)


def evaluate_cna01_a(inventory: NetworkInventory) -> CNA01CriterionResult:
    """Evaluate CNA01-A: Ingress Restrictions.

    Check that no sensitive ports are exposed to unrestricted internet access.

    Args:
        inventory: Network inventory from Terraform

    Returns:
        CNA01CriterionResult with findings
    """
    criterion_def = CNA01_CRITERIA_DEFINITIONS["CNA01-A"]
    findings: list[CNA01Finding] = []

    for sg in inventory.security_groups:
        if sg.sensitive_ports_exposed:
            for exposed in sg.sensitive_ports_exposed:
                findings.append(
                    CNA01Finding(
                        resource=sg.resource_address,
                        issue=f"Sensitive port {exposed['port']} ({exposed['service']}) "
                        f"exposed to {exposed['cidr']}",
                        source_file=sg.source_file,
                        source_line=sg.source_line,
                        severity="high",
                        details=exposed,
                    )
                )

    status = "PASS" if not findings else "FAIL"
    reason = criterion_def["pass_reason"] if status == "PASS" else criterion_def["fail_reason"]

    return CNA01CriterionResult(
        id="CNA01-A",
        name=criterion_def["name"],
        description=criterion_def["description"],
        requirement=criterion_def["requirement"],
        status=status,
        findings=findings,
    )


def evaluate_cna01_b(inventory: NetworkInventory) -> CNA01CriterionResult:
    """Evaluate CNA01-B: Explicit Ingress Rules.

    Check that all security groups have explicitly defined ingress rules.

    Args:
        inventory: Network inventory from Terraform

    Returns:
        CNA01CriterionResult with findings
    """
    criterion_def = CNA01_CRITERIA_DEFINITIONS["CNA01-B"]
    findings: list[CNA01Finding] = []

    for sg in inventory.security_groups:
        if not sg.has_explicit_ingress:
            findings.append(
                CNA01Finding(
                    resource=sg.resource_address,
                    issue="No ingress rules defined. Security groups must have "
                    "explicitly configured ingress restrictions.",
                    source_file=sg.source_file,
                    source_line=sg.source_line,
                    severity="high",
                )
            )

    status = "PASS" if not findings else "FAIL"

    return CNA01CriterionResult(
        id="CNA01-B",
        name=criterion_def["name"],
        description=criterion_def["description"],
        requirement=criterion_def["requirement"],
        status=status,
        findings=findings,
    )


def evaluate_cna01_c(inventory: NetworkInventory) -> CNA01CriterionResult:
    """Evaluate CNA01-C: Egress Restrictions.

    Check that outbound traffic is explicitly limited (no unrestricted egress).

    Args:
        inventory: Network inventory from Terraform

    Returns:
        CNA01CriterionResult with findings
    """
    criterion_def = CNA01_CRITERIA_DEFINITIONS["CNA01-C"]
    findings: list[CNA01Finding] = []

    for sg in inventory.security_groups:
        # Check for unrestricted egress
        if sg.has_unrestricted_egress:
            # Find the specific unrestricted egress rules
            for egress in sg.egress_rules:
                if egress.is_unrestricted:
                    cidrs = egress.cidr_blocks + egress.ipv6_cidr_blocks
                    unrestricted_cidrs = [
                        c for c in cidrs if c in ("0.0.0.0/0", "::/0")
                    ]
                    findings.append(
                        CNA01Finding(
                            resource=sg.resource_address,
                            issue=f"Unrestricted egress: {unrestricted_cidrs} on "
                            f"protocol {egress.protocol} ports {egress.from_port}-{egress.to_port}",
                            source_file=sg.source_file,
                            source_line=sg.source_line,
                            severity="high",
                            details={
                                "cidr_blocks": unrestricted_cidrs,
                                "protocol": egress.protocol,
                                "from_port": egress.from_port,
                                "to_port": egress.to_port,
                            },
                        )
                    )
        # Also fail if no egress rules are defined (AWS defaults to allow all)
        elif not sg.has_explicit_egress:
            findings.append(
                CNA01Finding(
                    resource=sg.resource_address,
                    issue="No egress rules defined. AWS defaults to allow all egress, "
                    "which violates the requirement to limit outbound traffic.",
                    source_file=sg.source_file,
                    source_line=sg.source_line,
                    severity="high",
                )
            )

    status = "PASS" if not findings else "FAIL"

    return CNA01CriterionResult(
        id="CNA01-C",
        name=criterion_def["name"],
        description=criterion_def["description"],
        requirement=criterion_def["requirement"],
        status=status,
        findings=findings,
    )


def evaluate_cna01_d(trigger_event: str) -> CNA01CriterionResult:
    """Evaluate CNA01-D: Persistent Evaluation.

    Check that evaluation is triggered by scheduled automation.

    Args:
        trigger_event: GitHub event that triggered the workflow

    Returns:
        CNA01CriterionResult with findings
    """
    criterion_def = CNA01_CRITERIA_DEFINITIONS["CNA01-D"]
    findings: list[CNA01Finding] = []

    if trigger_event != "schedule":
        findings.append(
            CNA01Finding(
                resource="workflow",
                issue=f"Workflow triggered by '{trigger_event}' instead of 'schedule'. "
                "Persistent evaluation requires scheduled automation.",
                source_file=".github/workflows/fedramp-ksi-evidence.yml",
                severity="medium",
                details={"trigger_event": trigger_event},
            )
        )

    status = "PASS" if not findings else "FAIL"

    return CNA01CriterionResult(
        id="CNA01-D",
        name=criterion_def["name"],
        description=criterion_def["description"],
        requirement=criterion_def["requirement"],
        status=status,
        findings=findings,
    )


def evaluate_cna01(
    inventory: NetworkInventory,
    trigger_event: str,
) -> tuple[dict[str, CNA01CriterionResult], CNA01Summary]:
    """Evaluate all CNA-01 criteria.

    Args:
        inventory: Network inventory from Terraform
        trigger_event: GitHub event that triggered the workflow

    Returns:
        Tuple of (criteria dict, summary)
    """
    # Check if we have any security groups to evaluate
    if not inventory.security_groups:
        # No security groups found - this is an ERROR condition
        return _build_error_result()

    # Evaluate each criterion
    criteria: dict[str, CNA01CriterionResult] = {}

    criteria["CNA01-A"] = evaluate_cna01_a(inventory)
    criteria["CNA01-B"] = evaluate_cna01_b(inventory)
    criteria["CNA01-C"] = evaluate_cna01_c(inventory)
    criteria["CNA01-D"] = evaluate_cna01_d(trigger_event)

    # Compute summary
    passed = sum(1 for c in criteria.values() if c.status == "PASS")
    failed = sum(1 for c in criteria.values() if c.status == "FAIL")
    total = len(criteria)

    # Count compliant security groups
    compliant_sgs = 0
    non_compliant_sgs = 0

    for sg in inventory.security_groups:
        is_compliant = (
            not sg.sensitive_ports_exposed
            and sg.has_explicit_ingress
            and sg.has_explicit_egress
            and not sg.has_unrestricted_egress
        )
        if is_compliant:
            compliant_sgs += 1
        else:
            non_compliant_sgs += 1

    # Determine overall status
    has_error = any(c.status == "ERROR" for c in criteria.values())
    has_fail = any(c.status == "FAIL" for c in criteria.values())

    if has_error:
        overall_status = "ERROR"
    elif has_fail:
        overall_status = "FAIL"
    else:
        overall_status = "PASS"

    summary = CNA01Summary(
        status=overall_status,
        passed_criteria=passed,
        failed_criteria=failed,
        total_criteria=total,
        security_groups_evaluated=len(inventory.security_groups),
        security_groups_compliant=compliant_sgs,
        security_groups_non_compliant=non_compliant_sgs,
    )

    return criteria, summary


def _build_error_result() -> tuple[dict[str, CNA01CriterionResult], CNA01Summary]:
    """Build an ERROR result when no security groups are found.

    Returns:
        Tuple of (criteria dict, summary) with ERROR status
    """
    error_finding = CNA01Finding(
        resource="network_inventory",
        issue="No security groups detected in Terraform configuration. "
        "Cannot evaluate network traffic restrictions.",
        source_file="",
        severity="high",
    )

    criteria: dict[str, CNA01CriterionResult] = {}

    for criterion_id, criterion_def in CNA01_CRITERIA_DEFINITIONS.items():
        if criterion_id == "CNA01-D":
            # Skip persistent evaluation for error case
            continue

        criteria[criterion_id] = CNA01CriterionResult(
            id=criterion_id,
            name=criterion_def["name"],
            description=criterion_def["description"],
            requirement=criterion_def["requirement"],
            status="ERROR",
            findings=[error_finding],
        )

    summary = CNA01Summary(
        status="ERROR",
        passed_criteria=0,
        failed_criteria=0,
        total_criteria=len(criteria),
        security_groups_evaluated=0,
        security_groups_compliant=0,
        security_groups_non_compliant=0,
    )

    return criteria, summary
