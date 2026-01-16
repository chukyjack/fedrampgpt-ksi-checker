# Test Terraform configuration - CNA-01 FAIL scenario
# This represents a NON-COMPLIANT network configuration that should fail CNA-01 evaluation
#
# CNA-01 Violations:
# - CNA01-A: SSH (22) exposed to 0.0.0.0/0
# - CNA01-B: One security group has no ingress rules
# - CNA01-C: Unrestricted egress (0.0.0.0/0 all ports)

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "non-compliant-vpc"
  }
}

# Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw"
  }
}

# VIOLATION: Web Security Group with sensitive ports exposed
# CNA01-A: FAIL - SSH (22) exposed to 0.0.0.0/0
# CNA01-C: FAIL - Unrestricted egress
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group - NON-COMPLIANT"
  vpc_id      = aws_vpc.main.id

  # CNA01-A VIOLATION: SSH exposed to internet
  ingress {
    description = "SSH from anywhere - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # This is fine - HTTPS from internet
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-C VIOLATION: Unrestricted egress
  egress {
    description = "Allow all outbound - INSECURE"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-sg-insecure"
  }
}

# VIOLATION: Database Security Group with multiple issues
# CNA01-A: FAIL - PostgreSQL (5432) exposed to 0.0.0.0/0
# CNA01-A: FAIL - MySQL (3306) exposed to 0.0.0.0/0
# CNA01-C: FAIL - Unrestricted egress
resource "aws_security_group" "db" {
  name        = "db-sg"
  description = "Database security group - NON-COMPLIANT"
  vpc_id      = aws_vpc.main.id

  # CNA01-A VIOLATION: PostgreSQL exposed to internet
  ingress {
    description = "PostgreSQL from anywhere - INSECURE"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-A VIOLATION: MySQL exposed to internet
  ingress {
    description = "MySQL from anywhere - INSECURE"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-C VIOLATION: Unrestricted egress
  egress {
    description = "Allow all outbound - INSECURE"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-sg-insecure"
  }
}

# VIOLATION: Management Security Group with RDP exposed
# CNA01-A: FAIL - RDP (3389) exposed to 0.0.0.0/0
# CNA01-C: FAIL - Unrestricted egress
resource "aws_security_group" "mgmt" {
  name        = "mgmt-sg"
  description = "Management security group - NON-COMPLIANT"
  vpc_id      = aws_vpc.main.id

  # CNA01-A VIOLATION: RDP exposed to internet
  ingress {
    description = "RDP from anywhere - INSECURE"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-C VIOLATION: Unrestricted egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mgmt-sg-insecure"
  }
}

# VIOLATION: Empty Security Group
# CNA01-B: FAIL - No ingress rules defined
resource "aws_security_group" "empty" {
  name        = "empty-sg"
  description = "Empty security group with no rules - NON-COMPLIANT"
  vpc_id      = aws_vpc.main.id

  # CNA01-B VIOLATION: No ingress rules at all
  # (Default AWS egress is implicit allow-all, which is also a violation)

  tags = {
    Name = "empty-sg-no-rules"
  }
}

# VIOLATION: Redis exposed to internet
# CNA01-A: FAIL - Redis (6379) exposed to 0.0.0.0/0
resource "aws_security_group" "cache" {
  name        = "cache-sg"
  description = "Cache security group - NON-COMPLIANT"
  vpc_id      = aws_vpc.main.id

  # CNA01-A VIOLATION: Redis exposed to internet
  ingress {
    description = "Redis from anywhere - INSECURE"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-C VIOLATION: Unrestricted egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cache-sg-insecure"
  }
}

# Application Load Balancer (the LB itself isn't the violation, the SG is)
resource "aws_lb" "main" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web.id]
  subnets            = [aws_subnet.public.id]

  tags = {
    Name = "main-alb"
  }
}
