"""Pydantic schemas for network-related KSI evidence artifacts.

These schemas define the structure for network inventory and CNA KSI evaluations.
Shared across CNA-01, CNA-02, CNA-03, and CNA-06.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --- Network Inventory Schemas ---


class IngressRule(BaseModel):
    """A single ingress rule on a security group."""

    description: str | None = None
    from_port: int | None = Field(None, description="Start port (-1 for all)")
    to_port: int | None = Field(None, description="End port (-1 for all)")
    protocol: str = Field(description="Protocol: tcp, udp, icmp, or -1 for all")
    cidr_blocks: list[str] = Field(default_factory=list)
    ipv6_cidr_blocks: list[str] = Field(default_factory=list)
    security_group_refs: list[str] = Field(
        default_factory=list,
        description="References to other security groups (e.g., aws_security_group.app)",
    )
    self_reference: bool = Field(
        default=False, description="Whether rule references its own security group"
    )
    is_unrestricted: bool = Field(
        default=False, description="True if 0.0.0.0/0 or ::/0 with all ports"
    )


class EgressRule(BaseModel):
    """A single egress rule on a security group."""

    description: str | None = None
    from_port: int | None = Field(None, description="Start port (-1 for all)")
    to_port: int | None = Field(None, description="End port (-1 for all)")
    protocol: str = Field(description="Protocol: tcp, udp, icmp, or -1 for all")
    cidr_blocks: list[str] = Field(default_factory=list)
    ipv6_cidr_blocks: list[str] = Field(default_factory=list)
    security_group_refs: list[str] = Field(default_factory=list)
    self_reference: bool = Field(default=False)
    is_unrestricted: bool = Field(
        default=False, description="True if 0.0.0.0/0 or ::/0 with all ports"
    )


class SecurityGroupInfo(BaseModel):
    """Security group extracted from Terraform configuration."""

    resource_address: str = Field(description="Terraform resource address (e.g., aws_security_group.web)")
    name: str | None = None
    description: str | None = None
    vpc_id: str | None = Field(None, description="VPC reference or ID")
    source_file: str
    source_line: int | None = None
    ingress_rules: list[IngressRule] = Field(default_factory=list)
    egress_rules: list[EgressRule] = Field(default_factory=list)
    has_explicit_ingress: bool = Field(
        default=False, description="Whether any ingress rules are defined"
    )
    has_explicit_egress: bool = Field(
        default=False, description="Whether any egress rules are defined"
    )
    has_unrestricted_ingress: bool = Field(
        default=False, description="Whether any ingress rule allows 0.0.0.0/0 on all ports"
    )
    has_unrestricted_egress: bool = Field(
        default=False, description="Whether any egress rule allows 0.0.0.0/0 on all ports"
    )
    sensitive_ports_exposed: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of sensitive ports exposed to 0.0.0.0/0",
    )


class VPCInfo(BaseModel):
    """VPC extracted from Terraform configuration."""

    resource_address: str
    cidr_block: str | None = None
    source_file: str
    source_line: int | None = None


class SubnetInfo(BaseModel):
    """Subnet extracted from Terraform configuration."""

    resource_address: str
    vpc_ref: str | None = None
    cidr_block: str | None = None
    is_public: bool = Field(
        default=False,
        description="True if subnet has map_public_ip_on_launch or route to IGW",
    )
    availability_zone: str | None = None
    source_file: str
    source_line: int | None = None


class RouteInfo(BaseModel):
    """A single route in a route table."""

    destination: str = Field(description="Destination CIDR block")
    target_type: str = Field(
        description="Type of target: internet_gateway, nat_gateway, vpc_peering, etc."
    )
    target_ref: str | None = Field(None, description="Terraform reference to target")


class RouteTableInfo(BaseModel):
    """Route table extracted from Terraform configuration."""

    resource_address: str
    vpc_ref: str | None = None
    routes: list[RouteInfo] = Field(default_factory=list)
    source_file: str
    source_line: int | None = None


class InternetGatewayInfo(BaseModel):
    """Internet gateway extracted from Terraform configuration."""

    resource_address: str
    vpc_ref: str | None = None
    source_file: str
    source_line: int | None = None


class NATGatewayInfo(BaseModel):
    """NAT gateway extracted from Terraform configuration."""

    resource_address: str
    subnet_ref: str | None = None
    source_file: str
    source_line: int | None = None


class LoadBalancerInfo(BaseModel):
    """Load balancer extracted from Terraform configuration."""

    resource_address: str
    type: str = Field(default="application", description="application or network")
    is_internal: bool = False
    security_group_refs: list[str] = Field(default_factory=list)
    subnet_refs: list[str] = Field(default_factory=list)
    source_file: str
    source_line: int | None = None


class NetworkInventory(BaseModel):
    """Complete network inventory extracted from Terraform configuration.

    This is the shared inventory used by CNA-01, CNA-02, CNA-03, and CNA-06.
    """

    schema_version: str = "1.0"
    extracted_at: str = Field(description="ISO 8601 timestamp")
    source_files: list[str] = Field(
        default_factory=list, description="Terraform files analyzed"
    )
    security_groups: list[SecurityGroupInfo] = Field(default_factory=list)
    vpcs: list[VPCInfo] = Field(default_factory=list)
    subnets: list[SubnetInfo] = Field(default_factory=list)
    route_tables: list[RouteTableInfo] = Field(default_factory=list)
    internet_gateways: list[InternetGatewayInfo] = Field(default_factory=list)
    nat_gateways: list[NATGatewayInfo] = Field(default_factory=list)
    load_balancers: list[LoadBalancerInfo] = Field(default_factory=list)


# --- CNA-01 Evaluation Schemas ---


class CNA01Finding(BaseModel):
    """A finding for CNA-01 evaluation."""

    resource: str = Field(description="Resource address with issue")
    issue: str = Field(description="Description of the issue")
    source_file: str
    source_line: int | None = None
    severity: str = Field(default="high", description="high, medium, or low")
    details: dict[str, Any] | None = None


class CNA01CriterionResult(BaseModel):
    """Result for a single CNA-01 criterion."""

    id: str = Field(description="Criterion ID (e.g., CNA01-A)")
    name: str = Field(description="Human-readable criterion name")
    description: str = Field(description="What this criterion checks")
    requirement: str = Field(default="required", description="required or recommended")
    status: str = Field(description="PASS, FAIL, or ERROR")
    findings: list[CNA01Finding] = Field(default_factory=list)


class CNA01Summary(BaseModel):
    """Summary of CNA-01 evaluation."""

    status: str = Field(description="Overall status: PASS, FAIL, or ERROR")
    passed_criteria: int
    failed_criteria: int
    total_criteria: int
    security_groups_evaluated: int
    security_groups_compliant: int
    security_groups_non_compliant: int


class CNA01EvaluationManifest(BaseModel):
    """Schema for CNA-01 evaluation_manifest.json."""

    schema_version: str = "1.0"
    ksi_id: str = "KSI-CNA-01"
    ksi_name: str = "Restrict Network Traffic"
    ksi_description: str = Field(
        default="Persistently ensure all machine-based information resources are "
        "configured to limit inbound and outbound network traffic."
    )
    applies_to: list[str] = Field(default_factory=lambda: ["Low", "Moderate"])
    related_controls: list[str] = Field(
        default_factory=lambda: ["AC-17.3", "CA-9", "CM-7.1", "SC-7.5", "SI-8"]
    )
    evaluated_at: str = Field(description="ISO 8601 timestamp")
    trigger_event: str = Field(description="GitHub event that triggered evaluation")
    repository: str
    commit_sha: str
    criteria: dict[str, CNA01CriterionResult] = Field(default_factory=dict)
    summary: CNA01Summary


# --- Multi-KSI Results Schema ---


class KSIResult(BaseModel):
    """Result for a single KSI in multi-KSI output."""

    ksi_id: str
    ksi_name: str
    status: str = Field(description="PASS, FAIL, or ERROR")
    evidence_path: str = Field(description="Path to evaluation manifest")


class MultiKSIResults(BaseModel):
    """Schema for results.json with multiple KSIs."""

    schema_version: str = "1.0"
    evaluated_at: str = Field(description="ISO 8601 timestamp")
    trigger_event: str
    repository: str
    commit_sha: str
    ksi_results: list[KSIResult] = Field(default_factory=list)
