# FedRAMP High / IL5 Logging and Monitoring Policies
#
# This policy validates logging configurations required by
# FedRAMP High and DoD IL5 compliance:
#
# - CloudTrail must be enabled
# - VPC Flow logs must be enabled
# - CloudWatch log groups must have appropriate retention
# - GuardDuty must be enabled
# - Config must be enabled

package fedramp.logging

import future.keywords.contains
import future.keywords.if
import future.keywords.in

#------------------------------------------------------------------------------
# CloudTrail Policies
#------------------------------------------------------------------------------

# Deny CloudTrail with logging disabled
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] != "delete"

    not resource.change.after.enable_logging

    msg := sprintf(
        "CloudTrail '%s' has logging disabled. CloudTrail logging must be enabled for IL5 compliance.",
        [resource.address]
    )
}

# Deny CloudTrail without multi-region (for commercial AWS)
# Note: GovCloud may use single-region
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] != "delete"

    not resource.change.after.is_multi_region_trail

    msg := sprintf(
        "CloudTrail '%s' is not multi-region. Consider enabling multi-region for comprehensive audit coverage.",
        [resource.address]
    )
}

# Deny CloudTrail without log file validation
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] != "delete"

    not resource.change.after.enable_log_file_validation

    msg := sprintf(
        "CloudTrail '%s' does not have log file validation enabled. Log validation is required for IL5 to ensure integrity.",
        [resource.address]
    )
}

# Deny CloudTrail without encryption
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_key_id

    msg := sprintf(
        "CloudTrail '%s' is not encrypted with a KMS key. CloudTrail logs must be encrypted for IL5 compliance.",
        [resource.address]
    )
}

# Deny CloudTrail without CloudWatch integration
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] != "delete"

    not resource.change.after.cloud_watch_logs_group_arn

    msg := sprintf(
        "CloudTrail '%s' does not send logs to CloudWatch. Consider enabling CloudWatch integration for real-time monitoring.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# CloudWatch Log Group Policies
#------------------------------------------------------------------------------

# Deny log groups with retention less than 365 days for audit logs
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] != "delete"

    # Check if this is an audit-related log group
    is_audit_log_group(resource.address)

    retention := resource.change.after.retention_in_days
    retention != 0  # 0 means never expire
    retention < 365

    msg := sprintf(
        "CloudWatch Log Group '%s' has retention of %d days. Audit logs require minimum 365 days retention for IL5 compliance.",
        [resource.address, retention]
    )
}

# Warn on log groups without KMS encryption
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] != "delete"

    not resource.change.after.kms_key_id

    msg := sprintf(
        "CloudWatch Log Group '%s' is not encrypted with KMS. Consider using CMK encryption for IL5 compliance.",
        [resource.address]
    )
}

# Deny log groups with 0 retention (never expire) without explicit approval
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] != "delete"

    retention := resource.change.after.retention_in_days
    retention == 0

    msg := sprintf(
        "CloudWatch Log Group '%s' has no retention limit (never expires). Ensure this is intentional and cost-effective.",
        [resource.address]
    )
}

# Helper: Check if log group is audit-related
is_audit_log_group(address) if {
    contains(address, "audit")
}

is_audit_log_group(address) if {
    contains(address, "cloudtrail")
}

is_audit_log_group(address) if {
    contains(address, "security")
}

is_audit_log_group(address) if {
    contains(address, "flow-log")
}

#------------------------------------------------------------------------------
# GuardDuty Policies
#------------------------------------------------------------------------------

# Deny GuardDuty detector that is disabled
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_guardduty_detector"
    resource.change.actions[_] != "delete"

    not resource.change.after.enable

    msg := sprintf(
        "GuardDuty detector '%s' is disabled. GuardDuty must be enabled for IL5 threat detection.",
        [resource.address]
    )
}

# Warn if GuardDuty S3 protection is disabled
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_guardduty_detector"
    resource.change.actions[_] != "delete"

    datasources := resource.change.after.datasources[_]
    s3_logs := datasources.s3_logs[_]
    not s3_logs.enable

    msg := sprintf(
        "GuardDuty detector '%s' has S3 protection disabled. Consider enabling S3 protection for IL5.",
        [resource.address]
    )
}

# Warn if GuardDuty Kubernetes protection is disabled
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_guardduty_detector"
    resource.change.actions[_] != "delete"

    datasources := resource.change.after.datasources[_]
    k8s := datasources.kubernetes[_]
    audit_logs := k8s.audit_logs[_]
    not audit_logs.enable

    msg := sprintf(
        "GuardDuty detector '%s' has Kubernetes audit log protection disabled. Enable for EKS threat detection.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# Config Policies
#------------------------------------------------------------------------------

# Deny Config recorder that is disabled
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_config_configuration_recorder_status"
    resource.change.actions[_] != "delete"

    not resource.change.after.is_enabled

    msg := sprintf(
        "AWS Config recorder '%s' is disabled. Config must be enabled for IL5 compliance monitoring.",
        [resource.address]
    )
}

# Deny Config without global resource recording
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_config_configuration_recorder"
    resource.change.actions[_] != "delete"

    recording_group := resource.change.after.recording_group[_]
    not recording_group.all_supported
    not recording_group.include_global_resource_types

    msg := sprintf(
        "AWS Config recorder '%s' does not record all resources. Enable all_supported and include_global_resource_types for IL5.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# Security Hub Policies
#------------------------------------------------------------------------------

# Warn if Security Hub standards are not enabled
warn[msg] if {
    # Check if there's a Security Hub account but no standards subscriptions
    securityhub_account := input.resource_changes[_]
    securityhub_account.type == "aws_securityhub_account"
    securityhub_account.change.actions[_] != "delete"

    not has_security_hub_standards()

    msg := sprintf(
        "Security Hub is enabled but no compliance standards are subscribed. Enable NIST 800-53 or CIS standards for IL5.",
        [securityhub_account.address]
    )
}

# Helper: Check for Security Hub standards
has_security_hub_standards() if {
    resource := input.resource_changes[_]
    resource.type == "aws_securityhub_standards_subscription"
    resource.change.actions[_] != "delete"
}

#------------------------------------------------------------------------------
# EKS Cluster Logging
#------------------------------------------------------------------------------

# Deny EKS clusters without audit logging
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    log_types := resource.change.after.enabled_cluster_log_types
    not "audit" in log_types

    msg := sprintf(
        "EKS cluster '%s' does not have audit logging enabled. Audit logs are required for IL5 compliance.",
        [resource.address]
    )
}

# Warn if EKS cluster missing recommended log types
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    log_types := {lt | lt := resource.change.after.enabled_cluster_log_types[_]}
    recommended := {"api", "audit", "authenticator", "controllerManager", "scheduler"}
    missing := recommended - log_types

    count(missing) > 0

    msg := sprintf(
        "EKS cluster '%s' is missing recommended log types: %v. Consider enabling all log types for comprehensive monitoring.",
        [resource.address, missing]
    )
}

#------------------------------------------------------------------------------
# S3 Bucket Logging
#------------------------------------------------------------------------------

# Warn on S3 buckets without access logging
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    bucket_name := resource.change.after.bucket
    not has_s3_logging(bucket_name)

    # Exclude logging target buckets to avoid circular logging
    not contains(bucket_name, "logs")
    not contains(bucket_name, "logging")

    msg := sprintf(
        "S3 bucket '%s' does not have access logging enabled. Consider enabling S3 access logging for IL5.",
        [resource.address]
    )
}

# Helper: Check if S3 bucket has logging
has_s3_logging(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_logging"
    resource.change.actions[_] != "delete"
    resource.change.after.bucket == bucket_name
}

#------------------------------------------------------------------------------
# RDS Logging
#------------------------------------------------------------------------------

# Warn on RDS instances without enabled logs
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.actions[_] != "delete"

    logs := resource.change.after.enabled_cloudwatch_logs_exports
    count(logs) == 0

    msg := sprintf(
        "RDS instance '%s' does not export logs to CloudWatch. Enable log exports for IL5 compliance.",
        [resource.address]
    )
}
