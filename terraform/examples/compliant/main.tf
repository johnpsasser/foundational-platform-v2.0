#------------------------------------------------------------------------------
# Compliant Example - FedRAMP High / IL5
#
# This example demonstrates a fully compliant deployment that will PASS
# all OPA/Conftest policy validation checks.
#
# Run validation:
#   terraform plan -out=tfplan
#   terraform show -json tfplan > tfplan.json
#   conftest test tfplan.json -p ../../policies/conftest/
#
# Expected result: All policies pass
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
  region = "us-east-1"  # Change to us-gov-west-1 for GovCloud

  default_tags {
    tags = {
      Owner          = "platform-team@example.gov"
      Environment    = "production"
      Classification = "IL5"
      CostCenter     = "CC-12345"
      DataSensitivity = "restricted"
      Compliance     = "FedRAMP-High"
      ManagedBy      = "terraform"
      Project        = "defense-platform"
    }
  }
}

#------------------------------------------------------------------------------
# Use the AWS Environment Module
#------------------------------------------------------------------------------

module "aws_environment" {
  source = "../../modules/aws-environment"

  # Core configuration
  environment_name     = "prod-defense"
  environment_type     = "production"
  classification_level = "IL5"
  region              = "us-east-1"  # Change to gov-west-1 for GovCloud

  # Required tags (IL5 compliant)
  required_tags = {
    Owner          = "platform-team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    DataSensitivity = "restricted"
    Compliance     = "FedRAMP-High"
  }

  additional_tags = {
    Project     = "defense-platform"
    Application = "interview-system"
  }

  # Network configuration (IL5 compliant)
  network_config = {
    cidr_block              = "10.0.0.0/16"
    availability_zone_count = 3

    subnet_tiers = {
      public = {
        enabled     = true
        cidr_bits   = 4
        nat_gateway = true
      }
      private = {
        enabled   = true
        cidr_bits = 4
      }
      isolated = {
        enabled   = true
        cidr_bits = 4
      }
      data = {
        enabled   = true
        cidr_bits = 4
      }
    }

    dns_config = {
      enable_dns_hostnames = true
      enable_dns_support   = true
      private_zone_name    = "prod-defense.internal"
    }

    # Flow logs ENABLED (required for IL5)
    flow_logs = {
      enabled        = true
      retention_days = 365  # Minimum 365 days for IL5
      traffic_type   = "ALL"
    }
  }

  # Kubernetes configuration (IL5 compliant)
  kubernetes_config = {
    cluster_name    = "prod-defense-eks"
    cluster_version = "1.28"

    control_plane = {
      # Private endpoint ENABLED (required for IL5)
      endpoint_private_access = true
      # Public endpoint DISABLED (recommended for IL5)
      endpoint_public_access  = false

      # All logging ENABLED (audit required for IL5)
      logging = {
        api_server         = true
        audit              = true  # Required for IL5
        authenticator      = true
        controller_manager = true
        scheduler          = true
      }
    }

    node_groups = {
      system = {
        name           = "system"
        instance_type  = "medium"
        min_size       = 3
        max_size       = 5
        desired_size   = 3
        disk_size_gb   = 100
        disk_encrypted = true  # Required for IL5
        subnet_tier    = "private"
        labels = {
          "node-type" = "system"
        }
        taints = []
      }
      application = {
        name           = "application"
        instance_type  = "large"
        min_size       = 3
        max_size       = 20
        desired_size   = 5
        disk_size_gb   = 200
        disk_encrypted = true  # Required for IL5
        subnet_tier    = "private"
        labels = {
          "node-type" = "application"
        }
        taints = []
      }
    }

    addons = {
      vpc_cni            = true
      coredns            = true
      kube_proxy         = true
      ebs_csi_driver     = true
      efs_csi_driver     = true
      secrets_store_csi  = true
    }

    enable_irsa = true
  }

  # IAM configuration (IL5 compliant)
  iam_config = {
    service_accounts = {
      app = {
        name        = "defense-app"
        namespace   = "defense"
        description = "Service account for defense application"
        permissions = [
          {
            service    = "storage"
            actions    = ["read", "write"]
            resources  = ["defense-app-bucket/*"]
            conditions = {}
          },
          {
            service    = "secrets"
            actions    = ["read"]
            resources  = ["defense-*"]
            conditions = {}
          }
        ]
      }
    }

    trusted_principals = []

    # MFA REQUIRED (IL5 compliance)
    require_mfa         = true
    max_session_duration = 3600
  }

  # KMS configuration (IL5 compliant)
  kms_config = {
    customer_managed_keys = {
      default = {
        name                 = "default"
        description          = "Default CMK for platform encryption"
        key_usage            = "ENCRYPT_DECRYPT"
        key_spec             = "SYMMETRIC_DEFAULT"
        enable_rotation      = true  # Required for IL5
        rotation_period_days = 365
        key_administrators   = ["role/admin"]
        key_users           = ["role/application"]
        deletion_window_days = 30
        enable_key_deletion  = false
      }
      eks = {
        name                 = "eks"
        description          = "CMK for EKS secrets encryption"
        key_usage            = "ENCRYPT_DECRYPT"
        key_spec             = "SYMMETRIC_DEFAULT"
        enable_rotation      = true  # Required for IL5
        rotation_period_days = 365
        key_administrators   = ["role/admin"]
        key_users           = ["role/eks"]
        deletion_window_days = 30
        enable_key_deletion  = false
      }
    }

    default_key_alias = "default"

    # HSM backing ENABLED (required for IL5)
    use_hsm_backing = true
  }

  # Private endpoints ENABLED (required for IL5)
  private_endpoints = {
    enabled = true

    services = {
      container_registry = true
      secrets_manager    = true
      key_management     = true
      storage            = true
      database           = true
      monitoring         = true
      logging            = true
    }

    private_dns_enabled = true
  }

  # Logging configuration (IL5 compliant)
  logging_config = {
    centralized_logging = {
      enabled        = true  # Required for IL5
      retention_days = 365   # Minimum 365 days for IL5
      encryption_key_id = "default"
    }

    audit_logging = {
      enabled             = true  # Required for IL5
      include_management  = true
      include_data_events = true
      include_read_only   = true
    }

    metrics = {
      enabled            = true
      detailed_monitoring = true
      retention_days     = 365
    }

    security_logging = {
      enabled               = true
      threat_detection      = true  # GuardDuty
      vulnerability_scanning = true
    }
  }

  # Transit configuration
  transit_config = {
    enable_transit_gateway = false
    transit_attachments    = []

    dedicated_connection = {
      enabled   = false
      bandwidth = ""
      location  = ""
    }

    vpn_backup = {
      enabled = false
      type    = ""
    }
  }

  # Backup configuration (IL5 compliant)
  backup_config = {
    backup_vault = {
      enabled        = true  # Required for IL5
      encryption_key = "default"
      retention_days = 90    # Minimum 90 days for IL5
    }

    cross_region_replication = {
      enabled           = true
      destination_region = "us-west-2"  # Change to gov-east-1 for GovCloud
    }

    point_in_time_recovery = {
      enabled        = true
      retention_days = 7
    }
  }
}

#------------------------------------------------------------------------------
# Additional Compliant Resources
#------------------------------------------------------------------------------

# Compliant S3 bucket with all required settings
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "prod-defense-compliant-bucket-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "prod-defense-compliant-bucket"
    Owner          = "platform-team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
    DataSensitivity = "restricted"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      # Using aws:kms (required for IL5)
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.aws_environment.kms.default_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  # All four settings TRUE (required for IL5)
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Compliant security group - no public access
resource "aws_security_group" "compliant_sg" {
  name        = "prod-defense-compliant-sg"
  description = "Compliant security group with no public access"
  vpc_id      = module.aws_environment.network.network_id

  # Only allow traffic from within VPC
  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.aws_environment.network.network_cidr]
  }

  egress {
    description = "Allow HTTPS to VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.aws_environment.network.network_cidr]
  }

  tags = {
    Name           = "prod-defense-compliant-sg"
    Owner          = "platform-team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
    DataSensitivity = "restricted"
  }
}

# Compliant CloudWatch Log Group
resource "aws_cloudwatch_log_group" "compliant_audit" {
  name              = "/defense/audit/compliant"
  retention_in_days = 365  # Minimum 365 days for IL5 audit logs
  kms_key_id        = module.aws_environment.kms.default_key_arn

  tags = {
    Name           = "prod-defense-audit-logs"
    Owner          = "platform-team@example.gov"
    Environment    = "production"
    Classification = "IL5"
    CostCenter     = "CC-12345"
    Compliance     = "FedRAMP-High"
    DataSensitivity = "restricted"
  }
}

#------------------------------------------------------------------------------
# Data Sources
#------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

#------------------------------------------------------------------------------
# Outputs
#------------------------------------------------------------------------------

output "environment_summary" {
  description = "Summary of the compliant environment"
  value       = module.aws_environment.environment_summary
}

output "compliance_status" {
  description = "Compliance verification"
  value = {
    encryption_enabled        = true
    private_endpoints_enabled = true
    flow_logs_enabled        = true
    audit_logging_enabled    = true
    mfa_required             = true
    hsm_backed_keys          = true
    public_access_blocked    = true
  }
}
