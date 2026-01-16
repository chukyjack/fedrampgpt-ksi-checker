# Test Terraform configuration - CNA-01 PASS scenario
# This represents a compliant network configuration that should pass CNA-01 evaluation
#
# CNA-01 Requirements:
# - CNA01-A: No sensitive ports exposed to 0.0.0.0/0
# - CNA01-B: All security groups have explicit ingress rules
# - CNA01-C: All security groups have restricted egress (not 0.0.0.0/0 all ports)

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
    Name = "fedramp-compliant-vpc"
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

# Private Subnet
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "private-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw"
  }
}

# NAT Gateway
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name = "main-nat"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "private-rt"
  }
}

# ALB Security Group - COMPLIANT
# - Ingress: Only HTTPS (443) from internet
# - Egress: Only to app tier on port 8080
resource "aws_security_group" "alb" {
  name        = "alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  # CNA01-A: PASS - Port 443 is not a sensitive port
  # CNA01-B: PASS - Explicit ingress rule defined
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CNA01-C: PASS - Egress is restricted to specific port and destination
  egress {
    description     = "To app tier"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name = "alb-sg"
  }
}

# App Tier Security Group - COMPLIANT
# - Ingress: Only from ALB on port 8080
# - Egress: Only to DB tier on port 5432
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Security group for application tier"
  vpc_id      = aws_vpc.main.id

  # CNA01-A: PASS - No internet exposure
  # CNA01-B: PASS - Explicit ingress rule defined
  ingress {
    description     = "From ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # CNA01-C: PASS - Egress is restricted to specific port and destination
  egress {
    description     = "To database tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db.id]
  }

  # Allow HTTPS outbound for external APIs (restricted to port 443)
  egress {
    description = "HTTPS to external APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "app-sg"
  }
}

# Database Tier Security Group - COMPLIANT
# - Ingress: Only from app tier on port 5432
# - Egress: None (databases don't need outbound)
resource "aws_security_group" "db" {
  name        = "db-sg"
  description = "Security group for database tier"
  vpc_id      = aws_vpc.main.id

  # CNA01-A: PASS - No internet exposure (5432 not exposed to 0.0.0.0/0)
  # CNA01-B: PASS - Explicit ingress rule defined
  ingress {
    description     = "PostgreSQL from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # CNA01-C: PASS - Self-referencing egress for replication only
  egress {
    description = "Replication"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true
  }

  tags = {
    Name = "db-sg"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id]

  tags = {
    Name = "main-alb"
  }
}
