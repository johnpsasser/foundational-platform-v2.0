# FedRAMP High / IL5 Encryption Compliance Policies
#
# This policy validates that all resources have encryption at rest enabled
# as required by FedRAMP High and DoD IL5 compliance requirements.
#
# Requirements:
# - All storage must be encrypted at rest
# - All databases must be encrypted at rest
# - All EBS volumes must be encrypted
# - All S3 buckets must have encryption enabled
# - All RDS instances must have encryption enabled
# - Customer-managed keys (CMK) required for IL5

package fedramp.encryption

import future.keywords.contains
import future.keywords.if
import future.keywords.in

#------------------------------------------------------------------------------
# S3 Bucket Encryption Policies
#------------------------------------------------------------------------------

# Deny S3 buckets without server-side encryption
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    # Check if there's a corresponding encryption configuration
    not has_s3_encryption(resource.change.after.bucket)

    msg := sprintf(
        "S3 bucket '%s' does not have server-side encryption configured. All S3 buckets must have encryption enabled for IL5 compliance.",
        [resource.address]
    )
}

# Deny S3 buckets without KMS encryption (SSE-KMS required for IL5)
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    rule := resource.change.after.rule[_]
    default_encryption := rule.apply_server_side_encryption_by_default
    default_encryption.sse_algorithm != "aws:kms"

    msg := sprintf(
        "S3 bucket encryption configuration '%s' uses %s. IL5 requires aws:kms encryption with customer-managed keys.",
        [resource.address, default_encryption.sse_algorithm]
    )
}

# Deny S3 buckets using AWS-managed KMS key (CMK required for IL5)
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    rule := resource.change.after.rule[_]
    default_encryption := rule.apply_server_side_encryption_by_default
    default_encryption.sse_algorithm == "aws:kms"
    not default_encryption.kms_master_key_id

    msg := sprintf(
        "S3 bucket encryption '%s' uses AWS-managed KMS key. IL5 recommends customer-managed keys (CMK) for better key control.",
        [resource.address]
    )
}

# Helper: Check if S3 bucket has encryption configuration
has_s3_encryption(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    resource.change.after.bucket == bucket_name
}

#------------------------------------------------------------------------------
# EBS Volume Encryption Policies
#------------------------------------------------------------------------------

# Deny unencrypted EBS volumes
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    resource.change.actions[_] != "delete"

    not resource.change.after.encrypted

    msg := sprintf(
        "EBS volume '%s' is not encrypted. All EBS volumes must be encrypted at rest for IL5 compliance.",
        [resource.address]
    )
}

# Warn if EBS volume not using CMK
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    resource.change.actions[_] != "delete"

    resource.change.after.encrypted
    not resource.change.after.kms_key_id

    msg := sprintf(
        "EBS volume '%s' is encrypted but not using a customer-managed key. IL5 recommends CMK for better key control.",
        [resource.address]
    )
}

# Deny EBS encryption by default not enabled
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_encryption_by_default"
    resource.change.actions[_] != "delete"

    not resource.change.after.enabled

    msg := sprintf(
        "EBS encryption by default '%s' is not enabled. EBS encryption must be enabled by default for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# RDS Database Encryption Policies
#------------------------------------------------------------------------------

# Deny unencrypted RDS instances
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.actions[_] != "delete"

    not resource.change.after.storage_encrypted

    msg := sprintf(
        "RDS instance '%s' does not have storage encryption enabled. All RDS instances must be encrypted for IL5 compliance.",
        [resource.address]
    )
}

# Deny unencrypted RDS clusters
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_rds_cluster"
    resource.change.actions[_] != "delete"

    not resource.change.after.storage_encrypted

    msg := sprintf(
        "RDS cluster '%s' does not have storage encryption enabled. All RDS clusters must be encrypted for IL5 compliance.",
        [resource.address]
    )
}

# Warn if RDS not using CMK
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_db_instance", "aws_rds_cluster"}
    resource.change.actions[_] != "delete"

    resource.change.after.storage_encrypted
    not resource.change.after.kms_key_id

    msg := sprintf(
        "RDS resource '%s' is encrypted but not using a customer-managed key. IL5 recommends CMK for better key control.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# EKS Cluster Encryption Policies
#------------------------------------------------------------------------------

# Deny EKS clusters without secrets encryption
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    # Check if encryption_config is present
    not resource.change.after.encryption_config

    msg := sprintf(
        "EKS cluster '%s' does not have secrets encryption configured. Kubernetes secrets must be encrypted with a CMK for IL5 compliance.",
        [resource.address]
    )
}

# Deny EKS clusters with empty encryption config
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    encryption_config := resource.change.after.encryption_config
    count(encryption_config) == 0

    msg := sprintf(
        "EKS cluster '%s' has empty encryption configuration. Kubernetes secrets must be encrypted with a CMK for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# KMS Key Policies
#------------------------------------------------------------------------------

# Deny KMS keys without rotation enabled
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.actions[_] != "delete"

    not resource.change.after.enable_key_rotation

    msg := sprintf(
        "KMS key '%s' does not have automatic key rotation enabled. Key rotation is required for IL5 compliance.",
        [resource.address]
    )
}

# Warn on short deletion window
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.actions[_] != "delete"

    deletion_window := resource.change.after.deletion_window_in_days
    deletion_window < 14

    msg := sprintf(
        "KMS key '%s' has a short deletion window of %d days. Consider increasing to at least 14 days for IL5 compliance.",
        [resource.address, deletion_window]
    )
}

#------------------------------------------------------------------------------
# CloudWatch Log Group Encryption
#------------------------------------------------------------------------------

# Warn if CloudWatch Log Groups not encrypted
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_key_id

    msg := sprintf(
        "CloudWatch Log Group '%s' is not encrypted with a CMK. Consider using KMS encryption for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# Secrets Manager Encryption
#------------------------------------------------------------------------------

# Warn if Secrets Manager secrets not using CMK
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_secretsmanager_secret"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_key_id

    msg := sprintf(
        "Secrets Manager secret '%s' is using AWS-managed key. IL5 recommends customer-managed keys for sensitive secrets.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# SNS Topic Encryption
#------------------------------------------------------------------------------

# Warn if SNS topics not encrypted
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_sns_topic"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_master_key_id

    msg := sprintf(
        "SNS topic '%s' is not encrypted. Consider using KMS encryption for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# SQS Queue Encryption
#------------------------------------------------------------------------------

# Deny SQS queues without encryption
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_sqs_queue"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_master_key_id
    not resource.change.after.sqs_managed_sse_enabled

    msg := sprintf(
        "SQS queue '%s' does not have encryption enabled. All SQS queues must be encrypted for IL5 compliance.",
        [resource.address]
    )
}
