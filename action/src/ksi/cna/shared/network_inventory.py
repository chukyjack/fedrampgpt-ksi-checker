"""Network inventory extraction from Terraform configuration.

Extracts security groups, VPCs, subnets, route tables, gateways, and load balancers
from Terraform HCL files. This inventory is shared across CNA-01, CNA-02, CNA-03, and CNA-06.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import hcl2

from shared.constants_cna import (
    ALL_PROTOCOLS,
    EXCLUDED_DIRS,
    SENSITIVE_PORTS,
    UNRESTRICTED_CIDRS,
)
from shared.schemas_network import (
    EgressRule,
    IngressRule,
    InternetGatewayInfo,
    LoadBalancerInfo,
    NATGatewayInfo,
    NetworkInventory,
    RouteInfo,
    RouteTableInfo,
    SecurityGroupInfo,
    SubnetInfo,
    VPCInfo,
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
        return None


def is_unrestricted_rule(
    cidr_blocks: list[str],
    ipv6_cidr_blocks: list[str],
    from_port: int | None,
    to_port: int | None,
    protocol: str,
) -> bool:
    """Check if a rule is unrestricted (0.0.0.0/0 or ::/0 with all ports).

    Args:
        cidr_blocks: List of IPv4 CIDR blocks
        ipv6_cidr_blocks: List of IPv6 CIDR blocks
        from_port: Start port
        to_port: End port
        protocol: Protocol string

    Returns:
        True if rule allows unrestricted access
    """
    # Check if any CIDR is unrestricted
    has_unrestricted_cidr = bool(
        set(cidr_blocks) & UNRESTRICTED_CIDRS
        or set(ipv6_cidr_blocks) & UNRESTRICTED_CIDRS
    )

    if not has_unrestricted_cidr:
        return False

    # Check if all ports/protocols are allowed
    is_all_protocols = protocol.lower() in ALL_PROTOCOLS

    # For protocol -1, ports are ignored (all traffic)
    if is_all_protocols:
        return True

    # Check for all ports (0-65535 or -1)
    if from_port is not None and to_port is not None:
        is_all_ports = (from_port == 0 and to_port == 65535) or (
            from_port == -1 or to_port == -1
        )
        return is_all_ports

    return False


def check_sensitive_port_exposure(
    cidr_blocks: list[str],
    ipv6_cidr_blocks: list[str],
    from_port: int | None,
    to_port: int | None,
    protocol: str,
) -> list[dict[str, Any]]:
    """Check if sensitive ports are exposed to 0.0.0.0/0.

    Args:
        cidr_blocks: List of IPv4 CIDR blocks
        ipv6_cidr_blocks: List of IPv6 CIDR blocks
        from_port: Start port
        to_port: End port
        protocol: Protocol string

    Returns:
        List of exposed sensitive ports with details
    """
    exposed = []

    # Check if rule allows access from anywhere
    has_unrestricted_cidr = bool(
        set(cidr_blocks) & UNRESTRICTED_CIDRS
        or set(ipv6_cidr_blocks) & UNRESTRICTED_CIDRS
    )

    if not has_unrestricted_cidr:
        return exposed

    # All protocols means all ports are potentially exposed
    if protocol.lower() in ALL_PROTOCOLS:
        for port, service in SENSITIVE_PORTS.items():
            exposed.append({
                "port": port,
                "service": service,
                "cidr": list(set(cidr_blocks) & UNRESTRICTED_CIDRS)
                or list(set(ipv6_cidr_blocks) & UNRESTRICTED_CIDRS),
            })
        return exposed

    # Check specific port range
    if from_port is None or to_port is None:
        return exposed

    for port, service in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            exposed.append({
                "port": port,
                "service": service,
                "cidr": list(set(cidr_blocks) & UNRESTRICTED_CIDRS)
                or list(set(ipv6_cidr_blocks) & UNRESTRICTED_CIDRS),
            })

    return exposed


def extract_security_group_rule(
    rule_config: dict[str, Any],
) -> tuple[
    int | None,
    int | None,
    str,
    list[str],
    list[str],
    list[str],
    bool,
    str | None,
]:
    """Extract common fields from an ingress or egress rule.

    Args:
        rule_config: Rule configuration dict

    Returns:
        Tuple of (from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks,
                 security_group_refs, self_reference, description)
    """
    from_port = rule_config.get("from_port")
    to_port = rule_config.get("to_port")
    protocol = str(rule_config.get("protocol", "-1"))
    description = rule_config.get("description")

    # Handle port values
    if isinstance(from_port, str):
        from_port = int(from_port) if from_port.lstrip("-").isdigit() else None
    if isinstance(to_port, str):
        to_port = int(to_port) if to_port.lstrip("-").isdigit() else None

    # CIDR blocks
    cidr_blocks = rule_config.get("cidr_blocks", [])
    if isinstance(cidr_blocks, str):
        cidr_blocks = [cidr_blocks]

    ipv6_cidr_blocks = rule_config.get("ipv6_cidr_blocks", [])
    if isinstance(ipv6_cidr_blocks, str):
        ipv6_cidr_blocks = [ipv6_cidr_blocks]

    # Security group references
    security_group_refs = []
    sg_ids = rule_config.get("security_groups", [])
    if isinstance(sg_ids, str):
        sg_ids = [sg_ids]
    security_group_refs.extend(sg_ids)

    # Source security group ID (for ingress)
    source_sg = rule_config.get("source_security_group_id")
    if source_sg:
        security_group_refs.append(source_sg)

    # Self reference
    self_ref = rule_config.get("self", False)
    if isinstance(self_ref, str):
        self_ref = self_ref.lower() == "true"

    return (
        from_port,
        to_port,
        protocol,
        cidr_blocks,
        ipv6_cidr_blocks,
        security_group_refs,
        self_ref,
        description,
    )


def extract_security_groups(
    parsed: dict[str, Any], file_path: str
) -> list[SecurityGroupInfo]:
    """Extract security groups from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of SecurityGroupInfo objects
    """
    security_groups: list[SecurityGroupInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        # AWS Security Group
        sg_resources = resource.get("aws_security_group", {})
        if isinstance(sg_resources, dict):
            for sg_name, sg_config in sg_resources.items():
                if not isinstance(sg_config, dict):
                    continue

                sg = _parse_security_group(
                    sg_name, sg_config, file_path, "aws_security_group"
                )
                security_groups.append(sg)

        # Azure Network Security Group
        nsg_resources = resource.get("azurerm_network_security_group", {})
        if isinstance(nsg_resources, dict):
            for nsg_name, nsg_config in nsg_resources.items():
                if not isinstance(nsg_config, dict):
                    continue

                nsg = _parse_azure_nsg(nsg_name, nsg_config, file_path)
                security_groups.append(nsg)

        # GCP Firewall Rule (each rule is separate, not grouped)
        fw_resources = resource.get("google_compute_firewall", {})
        if isinstance(fw_resources, dict):
            for fw_name, fw_config in fw_resources.items():
                if not isinstance(fw_config, dict):
                    continue

                fw = _parse_gcp_firewall(fw_name, fw_config, file_path)
                security_groups.append(fw)

    return security_groups


def _parse_security_group(
    name: str, config: dict[str, Any], file_path: str, resource_type: str
) -> SecurityGroupInfo:
    """Parse an AWS security group configuration.

    Args:
        name: Resource name
        config: Security group configuration
        file_path: Source file path
        resource_type: Terraform resource type

    Returns:
        SecurityGroupInfo object
    """
    ingress_rules: list[IngressRule] = []
    egress_rules: list[EgressRule] = []
    sensitive_ports_exposed: list[dict[str, Any]] = []

    # Parse ingress rules
    ingress_blocks = config.get("ingress", [])
    if isinstance(ingress_blocks, dict):
        ingress_blocks = [ingress_blocks]

    for ingress in ingress_blocks:
        if not isinstance(ingress, dict):
            continue

        (
            from_port,
            to_port,
            protocol,
            cidr_blocks,
            ipv6_cidr_blocks,
            sg_refs,
            self_ref,
            description,
        ) = extract_security_group_rule(ingress)

        is_unrestricted = is_unrestricted_rule(
            cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol
        )

        # Check for sensitive port exposure
        exposed = check_sensitive_port_exposure(
            cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol
        )
        sensitive_ports_exposed.extend(exposed)

        ingress_rules.append(
            IngressRule(
                description=description,
                from_port=from_port,
                to_port=to_port,
                protocol=protocol,
                cidr_blocks=cidr_blocks,
                ipv6_cidr_blocks=ipv6_cidr_blocks,
                security_group_refs=sg_refs,
                self_reference=self_ref,
                is_unrestricted=is_unrestricted,
            )
        )

    # Parse egress rules
    egress_blocks = config.get("egress", [])
    if isinstance(egress_blocks, dict):
        egress_blocks = [egress_blocks]

    for egress in egress_blocks:
        if not isinstance(egress, dict):
            continue

        (
            from_port,
            to_port,
            protocol,
            cidr_blocks,
            ipv6_cidr_blocks,
            sg_refs,
            self_ref,
            description,
        ) = extract_security_group_rule(egress)

        is_unrestricted = is_unrestricted_rule(
            cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol
        )

        egress_rules.append(
            EgressRule(
                description=description,
                from_port=from_port,
                to_port=to_port,
                protocol=protocol,
                cidr_blocks=cidr_blocks,
                ipv6_cidr_blocks=ipv6_cidr_blocks,
                security_group_refs=sg_refs,
                self_reference=self_ref,
                is_unrestricted=is_unrestricted,
            )
        )

    has_explicit_ingress = len(ingress_rules) > 0
    has_explicit_egress = len(egress_rules) > 0
    has_unrestricted_ingress = any(r.is_unrestricted for r in ingress_rules)
    has_unrestricted_egress = any(r.is_unrestricted for r in egress_rules)

    return SecurityGroupInfo(
        resource_address=f"{resource_type}.{name}",
        name=config.get("name"),
        description=config.get("description"),
        vpc_id=config.get("vpc_id"),
        source_file=file_path,
        ingress_rules=ingress_rules,
        egress_rules=egress_rules,
        has_explicit_ingress=has_explicit_ingress,
        has_explicit_egress=has_explicit_egress,
        has_unrestricted_ingress=has_unrestricted_ingress,
        has_unrestricted_egress=has_unrestricted_egress,
        sensitive_ports_exposed=sensitive_ports_exposed,
    )


def _parse_azure_nsg(
    name: str, config: dict[str, Any], file_path: str
) -> SecurityGroupInfo:
    """Parse an Azure Network Security Group configuration.

    Args:
        name: Resource name
        config: NSG configuration
        file_path: Source file path

    Returns:
        SecurityGroupInfo object
    """
    ingress_rules: list[IngressRule] = []
    egress_rules: list[EgressRule] = []
    sensitive_ports_exposed: list[dict[str, Any]] = []

    # Azure uses security_rule blocks
    rules = config.get("security_rule", [])
    if isinstance(rules, dict):
        rules = [rules]

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        direction = rule.get("direction", "").lower()
        access = rule.get("access", "").lower()

        # Skip deny rules
        if access != "allow":
            continue

        # Parse ports (Azure uses destination_port_range)
        port_range = rule.get("destination_port_range", "*")
        if port_range == "*":
            from_port, to_port = 0, 65535
        elif "-" in str(port_range):
            parts = str(port_range).split("-")
            from_port = int(parts[0])
            to_port = int(parts[1])
        else:
            from_port = to_port = int(port_range) if str(port_range).isdigit() else None

        protocol = rule.get("protocol", "*")
        if protocol == "*":
            protocol = "-1"

        # Source addresses
        cidr_blocks = []
        source = rule.get("source_address_prefix", "")
        if source in ("*", "Internet"):
            cidr_blocks = ["0.0.0.0/0"]
        elif source:
            cidr_blocks = [source]

        source_prefixes = rule.get("source_address_prefixes", [])
        if isinstance(source_prefixes, list):
            cidr_blocks.extend(source_prefixes)

        is_unrestricted = is_unrestricted_rule(
            cidr_blocks, [], from_port, to_port, protocol
        )

        if direction == "inbound":
            exposed = check_sensitive_port_exposure(
                cidr_blocks, [], from_port, to_port, protocol
            )
            sensitive_ports_exposed.extend(exposed)

            ingress_rules.append(
                IngressRule(
                    description=rule.get("description"),
                    from_port=from_port,
                    to_port=to_port,
                    protocol=protocol,
                    cidr_blocks=cidr_blocks,
                    is_unrestricted=is_unrestricted,
                )
            )
        else:
            egress_rules.append(
                EgressRule(
                    description=rule.get("description"),
                    from_port=from_port,
                    to_port=to_port,
                    protocol=protocol,
                    cidr_blocks=cidr_blocks,
                    is_unrestricted=is_unrestricted,
                )
            )

    return SecurityGroupInfo(
        resource_address=f"azurerm_network_security_group.{name}",
        name=config.get("name"),
        source_file=file_path,
        ingress_rules=ingress_rules,
        egress_rules=egress_rules,
        has_explicit_ingress=len(ingress_rules) > 0,
        has_explicit_egress=len(egress_rules) > 0,
        has_unrestricted_ingress=any(r.is_unrestricted for r in ingress_rules),
        has_unrestricted_egress=any(r.is_unrestricted for r in egress_rules),
        sensitive_ports_exposed=sensitive_ports_exposed,
    )


def _parse_gcp_firewall(
    name: str, config: dict[str, Any], file_path: str
) -> SecurityGroupInfo:
    """Parse a GCP firewall rule configuration.

    Args:
        name: Resource name
        config: Firewall configuration
        file_path: Source file path

    Returns:
        SecurityGroupInfo object
    """
    ingress_rules: list[IngressRule] = []
    egress_rules: list[EgressRule] = []
    sensitive_ports_exposed: list[dict[str, Any]] = []

    direction = config.get("direction", "INGRESS").upper()

    # Source/destination ranges
    source_ranges = config.get("source_ranges", [])
    if isinstance(source_ranges, str):
        source_ranges = [source_ranges]

    dest_ranges = config.get("destination_ranges", [])
    if isinstance(dest_ranges, str):
        dest_ranges = [dest_ranges]

    # Allow rules
    allow_blocks = config.get("allow", [])
    if isinstance(allow_blocks, dict):
        allow_blocks = [allow_blocks]

    for allow in allow_blocks:
        if not isinstance(allow, dict):
            continue

        protocol = allow.get("protocol", "all")
        if protocol == "all":
            protocol = "-1"

        ports = allow.get("ports", [])
        if isinstance(ports, str):
            ports = [ports]

        # Parse port ranges
        for port_spec in ports if ports else [None]:
            if port_spec is None:
                from_port, to_port = 0, 65535
            elif "-" in str(port_spec):
                parts = str(port_spec).split("-")
                from_port = int(parts[0])
                to_port = int(parts[1])
            else:
                from_port = to_port = int(port_spec)

            cidr_blocks = source_ranges if direction == "INGRESS" else dest_ranges

            is_unrestricted = is_unrestricted_rule(
                cidr_blocks, [], from_port, to_port, protocol
            )

            if direction == "INGRESS":
                exposed = check_sensitive_port_exposure(
                    cidr_blocks, [], from_port, to_port, protocol
                )
                sensitive_ports_exposed.extend(exposed)

                ingress_rules.append(
                    IngressRule(
                        description=config.get("description"),
                        from_port=from_port,
                        to_port=to_port,
                        protocol=protocol,
                        cidr_blocks=cidr_blocks,
                        is_unrestricted=is_unrestricted,
                    )
                )
            else:
                egress_rules.append(
                    EgressRule(
                        description=config.get("description"),
                        from_port=from_port,
                        to_port=to_port,
                        protocol=protocol,
                        cidr_blocks=cidr_blocks,
                        is_unrestricted=is_unrestricted,
                    )
                )

    return SecurityGroupInfo(
        resource_address=f"google_compute_firewall.{name}",
        name=config.get("name"),
        source_file=file_path,
        ingress_rules=ingress_rules,
        egress_rules=egress_rules,
        has_explicit_ingress=len(ingress_rules) > 0,
        has_explicit_egress=len(egress_rules) > 0,
        has_unrestricted_ingress=any(r.is_unrestricted for r in ingress_rules),
        has_unrestricted_egress=any(r.is_unrestricted for r in egress_rules),
        sensitive_ports_exposed=sensitive_ports_exposed,
    )


def extract_vpcs(parsed: dict[str, Any], file_path: str) -> list[VPCInfo]:
    """Extract VPCs from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of VPCInfo objects
    """
    vpcs: list[VPCInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        # AWS VPC
        vpc_resources = resource.get("aws_vpc", {})
        if isinstance(vpc_resources, dict):
            for vpc_name, vpc_config in vpc_resources.items():
                if isinstance(vpc_config, dict):
                    vpcs.append(
                        VPCInfo(
                            resource_address=f"aws_vpc.{vpc_name}",
                            cidr_block=vpc_config.get("cidr_block"),
                            source_file=file_path,
                        )
                    )

        # Azure Virtual Network
        vnet_resources = resource.get("azurerm_virtual_network", {})
        if isinstance(vnet_resources, dict):
            for vnet_name, vnet_config in vnet_resources.items():
                if isinstance(vnet_config, dict):
                    address_space = vnet_config.get("address_space", [])
                    cidr = address_space[0] if address_space else None
                    vpcs.append(
                        VPCInfo(
                            resource_address=f"azurerm_virtual_network.{vnet_name}",
                            cidr_block=cidr,
                            source_file=file_path,
                        )
                    )

        # GCP VPC Network
        gcp_vpc_resources = resource.get("google_compute_network", {})
        if isinstance(gcp_vpc_resources, dict):
            for gcp_vpc_name, gcp_vpc_config in gcp_vpc_resources.items():
                if isinstance(gcp_vpc_config, dict):
                    vpcs.append(
                        VPCInfo(
                            resource_address=f"google_compute_network.{gcp_vpc_name}",
                            cidr_block=None,  # GCP VPCs don't have a single CIDR
                            source_file=file_path,
                        )
                    )

    return vpcs


def extract_subnets(parsed: dict[str, Any], file_path: str) -> list[SubnetInfo]:
    """Extract subnets from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of SubnetInfo objects
    """
    subnets: list[SubnetInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        # AWS Subnet
        subnet_resources = resource.get("aws_subnet", {})
        if isinstance(subnet_resources, dict):
            for subnet_name, subnet_config in subnet_resources.items():
                if isinstance(subnet_config, dict):
                    # Check if public
                    map_public = subnet_config.get("map_public_ip_on_launch", False)
                    if isinstance(map_public, str):
                        map_public = map_public.lower() == "true"

                    subnets.append(
                        SubnetInfo(
                            resource_address=f"aws_subnet.{subnet_name}",
                            vpc_ref=subnet_config.get("vpc_id"),
                            cidr_block=subnet_config.get("cidr_block"),
                            is_public=map_public,
                            availability_zone=subnet_config.get("availability_zone"),
                            source_file=file_path,
                        )
                    )

    return subnets


def extract_route_tables(
    parsed: dict[str, Any], file_path: str
) -> list[RouteTableInfo]:
    """Extract route tables from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of RouteTableInfo objects
    """
    route_tables: list[RouteTableInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        # AWS Route Table
        rt_resources = resource.get("aws_route_table", {})
        if isinstance(rt_resources, dict):
            for rt_name, rt_config in rt_resources.items():
                if not isinstance(rt_config, dict):
                    continue

                routes: list[RouteInfo] = []

                # Parse route blocks
                route_blocks = rt_config.get("route", [])
                if isinstance(route_blocks, dict):
                    route_blocks = [route_blocks]

                for route in route_blocks:
                    if not isinstance(route, dict):
                        continue

                    destination = route.get("cidr_block", route.get("destination_cidr_block"))

                    # Determine target type
                    target_type = "unknown"
                    target_ref = None

                    if route.get("gateway_id"):
                        target_type = "internet_gateway"
                        target_ref = route["gateway_id"]
                    elif route.get("nat_gateway_id"):
                        target_type = "nat_gateway"
                        target_ref = route["nat_gateway_id"]
                    elif route.get("vpc_peering_connection_id"):
                        target_type = "vpc_peering"
                        target_ref = route["vpc_peering_connection_id"]
                    elif route.get("transit_gateway_id"):
                        target_type = "transit_gateway"
                        target_ref = route["transit_gateway_id"]
                    elif route.get("network_interface_id"):
                        target_type = "network_interface"
                        target_ref = route["network_interface_id"]

                    if destination:
                        routes.append(
                            RouteInfo(
                                destination=destination,
                                target_type=target_type,
                                target_ref=target_ref,
                            )
                        )

                route_tables.append(
                    RouteTableInfo(
                        resource_address=f"aws_route_table.{rt_name}",
                        vpc_ref=rt_config.get("vpc_id"),
                        routes=routes,
                        source_file=file_path,
                    )
                )

    return route_tables


def extract_internet_gateways(
    parsed: dict[str, Any], file_path: str
) -> list[InternetGatewayInfo]:
    """Extract internet gateways from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of InternetGatewayInfo objects
    """
    gateways: list[InternetGatewayInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        igw_resources = resource.get("aws_internet_gateway", {})
        if isinstance(igw_resources, dict):
            for igw_name, igw_config in igw_resources.items():
                if isinstance(igw_config, dict):
                    gateways.append(
                        InternetGatewayInfo(
                            resource_address=f"aws_internet_gateway.{igw_name}",
                            vpc_ref=igw_config.get("vpc_id"),
                            source_file=file_path,
                        )
                    )

    return gateways


def extract_nat_gateways(
    parsed: dict[str, Any], file_path: str
) -> list[NATGatewayInfo]:
    """Extract NAT gateways from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of NATGatewayInfo objects
    """
    gateways: list[NATGatewayInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        nat_resources = resource.get("aws_nat_gateway", {})
        if isinstance(nat_resources, dict):
            for nat_name, nat_config in nat_resources.items():
                if isinstance(nat_config, dict):
                    gateways.append(
                        NATGatewayInfo(
                            resource_address=f"aws_nat_gateway.{nat_name}",
                            subnet_ref=nat_config.get("subnet_id"),
                            source_file=file_path,
                        )
                    )

    return gateways


def extract_load_balancers(
    parsed: dict[str, Any], file_path: str
) -> list[LoadBalancerInfo]:
    """Extract load balancers from parsed Terraform.

    Args:
        parsed: Parsed HCL dict
        file_path: Source file path

    Returns:
        List of LoadBalancerInfo objects
    """
    load_balancers: list[LoadBalancerInfo] = []

    resource_blocks = parsed.get("resource", [])
    for resource in resource_blocks:
        if not isinstance(resource, dict):
            continue

        # AWS ALB/NLB
        lb_resources = resource.get("aws_lb", {})
        if isinstance(lb_resources, dict):
            for lb_name, lb_config in lb_resources.items():
                if isinstance(lb_config, dict):
                    is_internal = lb_config.get("internal", False)
                    if isinstance(is_internal, str):
                        is_internal = is_internal.lower() == "true"

                    sgs = lb_config.get("security_groups", [])
                    if isinstance(sgs, str):
                        sgs = [sgs]

                    subnets = lb_config.get("subnets", [])
                    if isinstance(subnets, str):
                        subnets = [subnets]

                    load_balancers.append(
                        LoadBalancerInfo(
                            resource_address=f"aws_lb.{lb_name}",
                            type=lb_config.get("load_balancer_type", "application"),
                            is_internal=is_internal,
                            security_group_refs=sgs,
                            subnet_refs=subnets,
                            source_file=file_path,
                        )
                    )

        # AWS ALB (legacy name)
        alb_resources = resource.get("aws_alb", {})
        if isinstance(alb_resources, dict):
            for alb_name, alb_config in alb_resources.items():
                if isinstance(alb_config, dict):
                    is_internal = alb_config.get("internal", False)
                    if isinstance(is_internal, str):
                        is_internal = is_internal.lower() == "true"

                    sgs = alb_config.get("security_groups", [])
                    if isinstance(sgs, str):
                        sgs = [sgs]

                    load_balancers.append(
                        LoadBalancerInfo(
                            resource_address=f"aws_alb.{alb_name}",
                            type="application",
                            is_internal=is_internal,
                            security_group_refs=sgs,
                            source_file=file_path,
                        )
                    )

    return load_balancers


def extract_network_inventory(
    root_path: str | Path = ".",
    tf_paths: list[str] | None = None,
) -> NetworkInventory:
    """Extract complete network inventory from Terraform configuration.

    Args:
        root_path: Root directory of the repository
        tf_paths: Optional list of specific paths to scan

    Returns:
        NetworkInventory with all extracted network resources
    """
    root = Path(root_path).resolve()

    all_security_groups: list[SecurityGroupInfo] = []
    all_vpcs: list[VPCInfo] = []
    all_subnets: list[SubnetInfo] = []
    all_route_tables: list[RouteTableInfo] = []
    all_internet_gateways: list[InternetGatewayInfo] = []
    all_nat_gateways: list[NATGatewayInfo] = []
    all_load_balancers: list[LoadBalancerInfo] = []
    source_files: list[str] = []

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
            dirnames[:] = [
                d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")
            ]

            current_dir = Path(dirpath)

            for filename in filenames:
                if not filename.endswith(".tf"):
                    continue

                file_path = current_dir / filename
                rel_path = str(file_path.relative_to(root))
                source_files.append(rel_path)

                # Parse file
                parsed = parse_tf_file(file_path)
                if parsed is None:
                    continue

                # Extract all network resources
                all_security_groups.extend(extract_security_groups(parsed, rel_path))
                all_vpcs.extend(extract_vpcs(parsed, rel_path))
                all_subnets.extend(extract_subnets(parsed, rel_path))
                all_route_tables.extend(extract_route_tables(parsed, rel_path))
                all_internet_gateways.extend(
                    extract_internet_gateways(parsed, rel_path)
                )
                all_nat_gateways.extend(extract_nat_gateways(parsed, rel_path))
                all_load_balancers.extend(extract_load_balancers(parsed, rel_path))

    return NetworkInventory(
        extracted_at=datetime.now(timezone.utc).isoformat(),
        source_files=sorted(source_files),
        security_groups=all_security_groups,
        vpcs=all_vpcs,
        subnets=all_subnets,
        route_tables=all_route_tables,
        internet_gateways=all_internet_gateways,
        nat_gateways=all_nat_gateways,
        load_balancers=all_load_balancers,
    )


if __name__ == "__main__":
    # Quick test
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = extract_network_inventory(path)
    print(json.dumps(result.model_dump(), indent=2))
