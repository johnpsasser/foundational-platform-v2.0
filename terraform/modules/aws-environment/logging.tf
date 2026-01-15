#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - Logging and Monitoring
#
# CloudWatch, CloudTrail, GuardDuty, Security Hub, and Config
# for FedRAMP High / IL4-IL5 compliance.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# CloudWatch Log Groups
#------------------------------------------------------------------------------

# Application logs
resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/${var.environment_name}/application"
  retention_in_days = var.logging_config.centralized_logging.retention_days
  kms_key_id        = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-application-logs"
    Purpose = "application"
  })
}

# Audit logs
resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/${var.environment_name}/audit"
  retention_in_days = var.logging_config.centralized_logging.retention_days
  kms_key_id        = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-audit-logs"
    Purpose = "audit"
  })
}

# Security logs
resource "aws_cloudwatch_log_group" "security" {
  name              = "/aws/${var.environment_name}/security"
  retention_in_days = var.logging_config.centralized_logging.retention_days
  kms_key_id        = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-security-logs"
    Purpose = "security"
  })
}

#------------------------------------------------------------------------------
# CloudTrail
#------------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false  # Single region for GovCloud
  enable_logging                = true
  kms_key_id                    = aws_kms_key.main[var.kms_config.default_key_alias].arn

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.audit.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn

  # Management events
  event_selector {
    read_write_type           = "All"
    include_management_events = var.logging_config.audit_logging.include_management
  }

  # Data events for S3 (if enabled)
  dynamic "event_selector" {
    for_each = var.logging_config.audit_logging.include_data_events ? [1] : []

    content {
      read_write_type           = "All"
      include_management_events = false

      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:${local.partition}:s3"]
      }
    }
  }

  # Data events for Lambda (if enabled)
  dynamic "event_selector" {
    for_each = var.logging_config.audit_logging.include_data_events ? [1] : []

    content {
      read_write_type           = "All"
      include_management_events = false

      data_resource {
        type   = "AWS::Lambda::Function"
        values = ["arn:${local.partition}:lambda"]
      }
    }
  }

  # Advanced event selectors for EKS
  advanced_event_selector {
    name = "Log EKS data events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field       = "resources.type"
      equals      = ["AWS::EKS::Cluster"]
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-cloudtrail"
  })

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# CloudTrail IAM role for CloudWatch
resource "aws_iam_role" "cloudtrail" {
  name = "${var.environment_name}-cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "${var.environment_name}-cloudtrail-policy"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.audit.arn}:*"
    }]
  })
}

#------------------------------------------------------------------------------
# GuardDuty
#------------------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  enable = var.logging_config.security_logging.threat_detection

  # S3 protection
  datasources {
    s3_logs {
      enable = true
    }

    kubernetes {
      audit_logs {
        enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  # Finding publishing frequency
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-guardduty"
  })
}

# GuardDuty S3 bucket for findings export
resource "aws_s3_bucket" "guardduty" {
  bucket = "${var.environment_name}-guardduty-findings-${local.account_id}"

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-guardduty-findings"
    Purpose = "security-findings"
  })
}

resource "aws_s3_bucket_versioning" "guardduty" {
  bucket = aws_s3_bucket.guardduty.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty" {
  bucket = aws_s3_bucket.guardduty.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main[var.kms_config.default_key_alias].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty" {
  bucket = aws_s3_bucket.guardduty.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#------------------------------------------------------------------------------
# Security Hub
#------------------------------------------------------------------------------

resource "aws_securityhub_account" "main" {
  enable_default_standards = false

  depends_on = [aws_guardduty_detector.main]
}

# Enable NIST 800-53 standard (FedRAMP)
resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:${local.partition}:securityhub:${local.aws_region}::standards/nist-800-53/v/5.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Enable CIS AWS Foundations
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:${local.partition}:securityhub:${local.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# Enable AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:${local.partition}:securityhub:${local.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

#------------------------------------------------------------------------------
# AWS Config
#------------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.environment_name}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.environment_name}-config-channel"
  s3_bucket_name = aws_s3_bucket.config.id
  sns_topic_arn  = aws_sns_topic.config.arn

  snapshot_delivery_properties {
    delivery_frequency = "Three_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# Config IAM role
resource "aws_iam_role" "config" {
  name = "${var.environment_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
  role       = aws_iam_role.config.name
}

resource "aws_iam_role_policy" "config_s3" {
  name = "${var.environment_name}-config-s3"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config.arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.config.arn
      }
    ]
  })
}

# Config S3 bucket
resource "aws_s3_bucket" "config" {
  bucket = "${var.environment_name}-config-${local.account_id}"

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-config"
    Purpose = "config-history"
  })
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main[var.kms_config.default_key_alias].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Config SNS topic
resource "aws_sns_topic" "config" {
  name              = "${var.environment_name}-config-notifications"
  kms_master_key_id = aws_kms_key.main[var.kms_config.default_key_alias].id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-config-notifications"
  })
}

#------------------------------------------------------------------------------
# AWS Backup
#------------------------------------------------------------------------------

resource "aws_backup_vault" "main" {
  name        = "${var.environment_name}-backup-vault"
  kms_key_arn = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-backup-vault"
  })
}

resource "aws_backup_plan" "main" {
  name = "${var.environment_name}-backup-plan"

  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 ? * * *)"  # Daily at 5 AM UTC

    lifecycle {
      delete_after = var.backup_config.backup_vault.retention_days
    }

    copy_action {
      lifecycle {
        delete_after = var.backup_config.backup_vault.retention_days * 2
      }
      destination_vault_arn = var.backup_config.cross_region_replication.enabled ? (
        "arn:${local.partition}:backup:${var.backup_config.cross_region_replication.destination_region}:${local.account_id}:backup-vault:${var.environment_name}-backup-vault-dr"
      ) : null
    }
  }

  rule {
    rule_name         = "weekly-backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 ? * SUN *)"  # Weekly on Sunday

    lifecycle {
      cold_storage_after = 30
      delete_after       = var.backup_config.backup_vault.retention_days * 4
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-backup-plan"
  })
}

# Backup selection
resource "aws_backup_selection" "main" {
  name         = "${var.environment_name}-backup-selection"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Environment"
    value = var.required_tags.Environment
  }

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

# Backup IAM role
resource "aws_iam_role" "backup" {
  name = "${var.environment_name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "backup.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
  role       = aws_iam_role.backup.name
}

resource "aws_iam_role_policy_attachment" "backup_restore" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
  role       = aws_iam_role.backup.name
}
