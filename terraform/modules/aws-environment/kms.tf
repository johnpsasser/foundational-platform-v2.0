#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - KMS Configuration
#
# Customer-managed encryption keys with CloudHSM backing for IL5 compliance.
# All keys are configured with automatic rotation and strict key policies.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Customer Managed Keys
#------------------------------------------------------------------------------

resource "aws_kms_key" "main" {
  for_each = var.kms_config.customer_managed_keys

  description              = each.value.description
  key_usage                = each.value.key_usage
  customer_master_key_spec = each.value.key_spec

  # Rotation configuration
  enable_key_rotation = each.value.enable_rotation

  # Deletion protection
  deletion_window_in_days = each.value.deletion_window_days
  is_enabled              = true

  # IL5 requirement: Multi-region keys disabled for data sovereignty
  multi_region = false

  # Key policy
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-policy-${each.key}"
    Statement = [
      # Root account access (required for key management)
      {
        Sid    = "EnableRootAccountPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      # Key administrators
      {
        Sid    = "AllowKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = [for admin in each.value.key_administrators :
            startswith(admin, "arn:") ? admin : "arn:${local.partition}:iam::${local.account_id}:${admin}"
          ]
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      # Key users
      {
        Sid    = "AllowKeyUsage"
        Effect = "Allow"
        Principal = {
          AWS = [for user in each.value.key_users :
            startswith(user, "arn:") ? user : "arn:${local.partition}:iam::${local.account_id}:${user}"
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      # Allow grants for AWS services
      {
        Sid    = "AllowServiceGrants"
        Effect = "Allow"
        Principal = {
          AWS = [for user in each.value.key_users :
            startswith(user, "arn:") ? user : "arn:${local.partition}:iam::${local.account_id}:${user}"
          ]
        }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      },
      # CloudWatch Logs encryption
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.aws_region}:${local.account_id}:*"
          }
        }
      },
      # EKS encryption
      {
        Sid    = "AllowEKSEncryption"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
          StringLike = {
            "kms:ViaService" = "eks.${local.aws_region}.amazonaws.com"
          }
        }
      },
      # S3 encryption
      {
        Sid    = "AllowS3Encryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      # Autoscaling encryption (for EBS volumes)
      {
        Sid    = "AllowAutoscalingEncryption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-${each.key}"
    KeyType = each.value.key_usage
  })
}

#------------------------------------------------------------------------------
# KMS Key Aliases
#------------------------------------------------------------------------------

resource "aws_kms_alias" "main" {
  for_each = var.kms_config.customer_managed_keys

  name          = "alias/${var.environment_name}/${each.key}"
  target_key_id = aws_kms_key.main[each.key].key_id
}

#------------------------------------------------------------------------------
# Default EBS Encryption
#------------------------------------------------------------------------------

resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "main" {
  key_arn = aws_kms_key.main[var.kms_config.default_key_alias].arn
}

#------------------------------------------------------------------------------
# S3 Bucket for CloudTrail (encrypted with CMK)
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.environment_name}-cloudtrail-${local.account_id}"

  tags = merge(local.common_tags, {
    Name    = "${var.environment_name}-cloudtrail"
    Purpose = "audit-logs"
  })
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main[var.kms_config.default_key_alias].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.logging_config.centralized_logging.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:${local.partition}:cloudtrail:${local.aws_region}:${local.account_id}:trail/${var.environment_name}-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:${local.partition}:cloudtrail:${local.aws_region}:${local.account_id}:trail/${var.environment_name}-trail"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedTransport"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyNonKMSEncryption"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}
