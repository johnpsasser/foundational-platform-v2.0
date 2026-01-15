#------------------------------------------------------------------------------
# NON-COMPLIANT Example - FedRAMP High / IL5 VIOLATIONS
#
# !! WARNING: This example demonstrates VIOLATIONS that will FAIL policy checks !!
#
# This file intentionally includes misconfigurations to demonstrate
# how OPA/Conftest policies catch compliance violations.
#
# Run validation:
#   terraform plan -out=tfplan
#   terraform show -json tfplan > tfplan.json
#   conftest test tfplan.json -p ../../policies/conftest/
#
# Expected result: Multiple policy violations detected
#
# VIOLATIONS IN THIS FILE:
# 1. [TAG-001] Missing required tags (Owner, Classification, etc.)
# 2. [TAG-002] Invalid Classification value
# 3. [TAG-004] IL5 without proper Compliance tag
# 4. [ENC-001] S3 bucket without KMS encryption
# 5. [ENC-002] Unencrypted EBS volume
# 6. [ENC-003] Unencrypted RDS instance
# 7. [ENC-005] KMS key without rotation
# 8. [NET-001] Security group with 0.0.0.0/0 ingress
# 9. [NET-002] SSH from anywhere (port 22)
# 10. [NET-003] Publicly accessible RDS
# 11. [NET-004] EKS without private endpoint
# 12. [NET-005] S3 bucket without full public access block
# 13. [LOG-001] CloudTrail with logging disabled
# 14. [LOG-003] GuardDuty disabled
# 15. [LOG-004] EKS without audit logging
# 16. [LOG-005] Audit log group with insufficient retention
#------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-gov-west-1"

  # VIOLATION: Not using default_tags means resources may miss required tags
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

#------------------------------------------------------------------------------
# VIOLATION [TAG-001]: S3 bucket missing required tags
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "missing_tags" {
  bucket = "noncompliant-missing-tags-${data.aws_caller_identity.current.account_id}"

  # VIOLATION: Missing ALL required tags:
  # - Owner
  # - Environment
  # - Classification
  # - CostCenter
  # - Compliance
  tags = {
    Name = "noncompliant-bucket"
    # Missing: Owner, Environment, Classification, CostCenter, Compliance
  }
}

#------------------------------------------------------------------------------
# VIOLATION [TAG-002]: Invalid Classification tag value
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "invalid_classification" {
  bucket = "noncompliant-invalid-class-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "noncompliant-invalid-classification"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "SECRET"  # VIOLATION: Must be IL4, IL5, or IL6
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [TAG-004]: IL5 without FedRAMP-High or DoD-IL5 compliance
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "wrong_compliance" {
  bucket = "noncompliant-wrong-compliance-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "noncompliant-wrong-compliance"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"         # IL5 classification...
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-Moderate"  # VIOLATION: IL5 requires FedRAMP-High or DoD-IL5
  }
}

#------------------------------------------------------------------------------
# VIOLATION [ENC-001]: S3 bucket without KMS encryption
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "no_kms" {
  bucket = "noncompliant-no-kms-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "noncompliant-no-kms"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "no_kms" {
  bucket = aws_s3_bucket.no_kms.id

  rule {
    apply_server_side_encryption_by_default {
      # VIOLATION: Using AES256 instead of aws:kms
      sse_algorithm = "AES256"  # Should be "aws:kms" for IL5
    }
  }
}

#------------------------------------------------------------------------------
# VIOLATION [ENC-002]: Unencrypted EBS volume
#------------------------------------------------------------------------------

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 100

  # VIOLATION: encrypted = false (must be true for IL5)
  encrypted = false

  tags = {
    Name           = "noncompliant-unencrypted-ebs"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [ENC-003]: Unencrypted RDS instance
#------------------------------------------------------------------------------

resource "aws_db_subnet_group" "noncompliant" {
  name       = "noncompliant-db-subnet"
  subnet_ids = ["subnet-placeholder1", "subnet-placeholder2"]  # Would need real subnet IDs

  tags = {
    Name           = "noncompliant-db-subnet"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

resource "aws_db_instance" "unencrypted" {
  identifier           = "noncompliant-unencrypted-rds"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  db_subnet_group_name = aws_db_subnet_group.noncompliant.name
  skip_final_snapshot  = true

  # VIOLATION: storage_encrypted = false (must be true for IL5)
  storage_encrypted = false

  # VIOLATION [NET-003]: publicly_accessible = true
  publicly_accessible = true

  tags = {
    Name           = "noncompliant-unencrypted-rds"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [ENC-005]: KMS key without rotation
#------------------------------------------------------------------------------

resource "aws_kms_key" "no_rotation" {
  description = "Non-compliant KMS key without rotation"

  # VIOLATION: enable_key_rotation = false (must be true for IL5)
  enable_key_rotation = false

  deletion_window_in_days = 7  # Also too short (should be >= 14)

  tags = {
    Name           = "noncompliant-no-rotation-key"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [NET-001] & [NET-002]: Security group with public SSH access
#------------------------------------------------------------------------------

resource "aws_security_group" "public_ssh" {
  name        = "noncompliant-public-ssh"
  description = "Non-compliant SG allowing SSH from anywhere"
  vpc_id      = "vpc-placeholder"  # Would need real VPC ID

  # VIOLATION [NET-002]: SSH from 0.0.0.0/0
  ingress {
    description = "SSH from anywhere - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Public SSH access
  }

  # VIOLATION [NET-001]: HTTPS from anywhere without approval tag
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Missing PublicIngressApproved tag
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Missing: PublicIngressApproved = "true" tag
  tags = {
    Name           = "noncompliant-public-ssh"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
    # Missing: PublicIngressApproved = "true"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [NET-004]: EKS without private endpoint
#------------------------------------------------------------------------------

resource "aws_eks_cluster" "no_private_endpoint" {
  name     = "noncompliant-eks-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-placeholder1", "subnet-placeholder2"]

    # VIOLATION: endpoint_private_access = false (must be true for IL5)
    endpoint_private_access = false
    # endpoint_public_access = true is also a concern
    endpoint_public_access  = true
  }

  # VIOLATION [LOG-004]: Missing audit logging
  enabled_cluster_log_types = [
    "api",
    # "audit",  # VIOLATION: audit is MISSING (required for IL5)
    "authenticator"
  ]

  # VIOLATION [ENC-004]: No encryption_config
  # encryption_config is missing entirely

  tags = {
    Name           = "noncompliant-eks-cluster"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [NET-005]: S3 bucket without full public access block
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "partial_block" {
  bucket = "noncompliant-partial-block-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "noncompliant-partial-block"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

resource "aws_s3_bucket_public_access_block" "partial_block" {
  bucket = aws_s3_bucket.partial_block.id

  # VIOLATION: Not all four settings are true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = false  # VIOLATION: Must be true
  restrict_public_buckets = false  # VIOLATION: Must be true
}

#------------------------------------------------------------------------------
# VIOLATION [LOG-001] & [LOG-002]: CloudTrail misconfigurations
#------------------------------------------------------------------------------

resource "aws_cloudtrail" "disabled" {
  name           = "noncompliant-cloudtrail"
  s3_bucket_name = aws_s3_bucket.missing_tags.id

  # VIOLATION [LOG-001]: enable_logging = false
  enable_logging = false

  # VIOLATION [LOG-002]: No KMS encryption
  # kms_key_id is missing

  # Additional issues
  enable_log_file_validation = false  # Should be true

  tags = {
    Name           = "noncompliant-cloudtrail"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [LOG-003]: GuardDuty disabled
#------------------------------------------------------------------------------

resource "aws_guardduty_detector" "disabled" {
  # VIOLATION: enable = false (must be true for IL5)
  enable = false

  tags = {
    Name           = "noncompliant-guardduty"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# VIOLATION [LOG-005]: Audit log group with insufficient retention
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "short_retention" {
  name = "/defense/audit/noncompliant"

  # VIOLATION: 90 days < 365 days required for audit logs
  retention_in_days = 90  # Must be at least 365 for IL5 audit logs

  # Also missing KMS encryption

  tags = {
    Name           = "noncompliant-audit-logs"
    Owner          = "team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
  }
}

#------------------------------------------------------------------------------
# Expected Policy Violations Summary
#------------------------------------------------------------------------------

output "expected_violations" {
  description = "List of expected policy violations in this example"
  value = {
    tag_violations = [
      "TAG-001: Missing required tags on aws_s3_bucket.missing_tags",
      "TAG-002: Invalid Classification 'SECRET' on aws_s3_bucket.invalid_classification",
      "TAG-004: IL5 with FedRAMP-Moderate compliance on aws_s3_bucket.wrong_compliance"
    ]
    encryption_violations = [
      "ENC-001: S3 bucket using AES256 instead of aws:kms",
      "ENC-002: Unencrypted EBS volume",
      "ENC-003: Unencrypted RDS instance",
      "ENC-004: EKS cluster without secrets encryption",
      "ENC-005: KMS key without rotation enabled"
    ]
    network_violations = [
      "NET-001: Security group allows 0.0.0.0/0 without approval",
      "NET-002: Security group allows SSH from 0.0.0.0/0",
      "NET-003: RDS instance is publicly accessible",
      "NET-004: EKS cluster missing private endpoint",
      "NET-005: S3 bucket public access block incomplete"
    ]
    logging_violations = [
      "LOG-001: CloudTrail logging disabled",
      "LOG-002: CloudTrail without KMS encryption",
      "LOG-003: GuardDuty detector disabled",
      "LOG-004: EKS cluster missing audit logging",
      "LOG-005: Audit log group retention < 365 days"
    ]
  }
}
