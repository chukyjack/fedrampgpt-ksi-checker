# Test Terraform configuration - ERROR scenario
# This has invalid syntax that will cause terraform validate to fail

terraform {
  required_version = ">= 1.0.0"
}

# Invalid resource - missing required arguments
resource "aws_instance" "broken" {
  # ami and instance_type are required but missing
  tags = {
    Name = "broken-instance"
  }
}

# Invalid reference
resource "aws_security_group" "invalid" {
  name   = "invalid-sg"
  vpc_id = aws_vpc.nonexistent.id  # References non-existent resource
}
