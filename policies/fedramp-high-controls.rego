# FedRAMP High Compliance Policy as Code
# NIST 800-53 Rev 5 Control Validation using Open Policy Agent (OPA)
#
# This policy file enforces FedRAMP High baseline controls during
# Terraform plan validation as part of the CI/CD pipeline.
#
# Controls Covered:
# - AC-3: Access Enforcement
# - AC-6: Least Privilege
# - AU-2: Event Logging
# - AU-9: Protection of Audit Information
# - CM-6: Configuration Settings
# - SC-7: Boundary Protection
# - SC-8: Transmission Confidentiality and Integrity
# - SC-13: Cryptographic Protection
# - SC-28: Protection of Information at Rest

package fedramp.high

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

# Check if resource is being created or updated
resource_changes[resource_type] := resources {
    resources := [r |
        r := input.resource_changes[_]
        r.type == resource_type
        r.change.actions[_] in ["create", "update"]
    ]
}

# Get resource after values
after_values(resource) := resource.change.after

# -----------------------------------------------------------------------------
# SC-13: Cryptographic Protection - KMS Key Validation
# -----------------------------------------------------------------------------

# Deny KMS keys without rotation enabled
deny_kms_no_rotation contains msg if {
    resources := resource_changes["aws_kms_key"]
    r := resources[_]
    values := after_values(r)
    values.enable_key_rotation != true
    msg := sprintf(
        "SC-13 VIOLATION: KMS key '%s' must have key rotation enabled for FedRAMP High compliance",
        [r.address]
    )
}

# Deny KMS keys with deletion window less than 30 days
deny_kms_short_deletion contains msg if {
    resources := resource_changes["aws_kms_key"]
    r := resources[_]
    values := after_values(r)
    values.deletion_window_in_days < 30
    msg := sprintf(
        "SC-13 VIOLATION: KMS key '%s' deletion window must be at least 30 days (current: %d)",
        [r.address, values.deletion_window_in_days]
    )
}

# -----------------------------------------------------------------------------
# SC-28: Protection of Information at Rest - S3 Encryption
# -----------------------------------------------------------------------------

# Deny S3 buckets without encryption
deny_s3_no_encryption contains msg if {
    resources := resource_changes["aws_s3_bucket"]
    r := resources[_]
    # Check if there's a corresponding encryption configuration
    not s3_has_encryption(r.address)
    msg := sprintf(
        "SC-28 VIOLATION: S3 bucket '%s' must have server-side encryption enabled",
        [r.address]
    )
}

s3_has_encryption(bucket_address) if {
    resources := resource_changes["aws_s3_bucket_server_side_encryption_configuration"]
    r := resources[_]
    contains(r.address, bucket_address)
}

# Deny S3 buckets without versioning
deny_s3_no_versioning contains msg if {
    resources := resource_changes["aws_s3_bucket"]
    r := resources[_]
    not s3_has_versioning(r.address)
    msg := sprintf(
        "AU-9 VIOLATION: S3 bucket '%s' must have versioning enabled to protect audit information",
        [r.address]
    )
}

s3_has_versioning(bucket_address) if {
    resources := resource_changes["aws_s3_bucket_versioning"]
    r := resources[_]
    contains(r.address, bucket_address)
    values := after_values(r)
    values.versioning_configuration[_].status == "Enabled"
}

# Deny S3 buckets with public access
deny_s3_public_access contains msg if {
    resources := resource_changes["aws_s3_bucket_public_access_block"]
    r := resources[_]
    values := after_values(r)
    not all_public_access_blocked(values)
    msg := sprintf(
        "AC-3 VIOLATION: S3 bucket '%s' must block all public access",
        [r.address]
    )
}

all_public_access_blocked(values) if {
    values.block_public_acls == true
    values.block_public_policy == true
    values.ignore_public_acls == true
    values.restrict_public_buckets == true
}

# -----------------------------------------------------------------------------
# SC-28: Protection of Information at Rest - RDS Encryption
# -----------------------------------------------------------------------------

# Deny RDS instances without encryption
deny_rds_no_encryption contains msg if {
    resources := resource_changes["aws_db_instance"]
    r := resources[_]
    values := after_values(r)
    values.storage_encrypted != true
    msg := sprintf(
        "SC-28 VIOLATION: RDS instance '%s' must have storage encryption enabled",
        [r.address]
    )
}

# Deny RDS instances without KMS CMK
deny_rds_no_cmk contains msg if {
    resources := resource_changes["aws_db_instance"]
    r := resources[_]
    values := after_values(r)
    values.storage_encrypted == true
    not values.kms_key_id
    msg := sprintf(
        "SC-13 VIOLATION: RDS instance '%s' must use customer-managed KMS key",
        [r.address]
    )
}

# Deny RDS instances in public subnets
deny_rds_publicly_accessible contains msg if {
    resources := resource_changes["aws_db_instance"]
    r := resources[_]
    values := after_values(r)
    values.publicly_accessible == true
    msg := sprintf(
        "SC-7 VIOLATION: RDS instance '%s' must not be publicly accessible",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# SC-28: Protection of Information at Rest - EBS Encryption
# -----------------------------------------------------------------------------

# Deny EBS volumes without encryption
deny_ebs_no_encryption contains msg if {
    resources := resource_changes["aws_ebs_volume"]
    r := resources[_]
    values := after_values(r)
    values.encrypted != true
    msg := sprintf(
        "SC-28 VIOLATION: EBS volume '%s' must have encryption enabled",
        [r.address]
    )
}

# Deny EC2 instances with unencrypted root volumes
deny_ec2_unencrypted_root contains msg if {
    resources := resource_changes["aws_instance"]
    r := resources[_]
    values := after_values(r)
    block := values.root_block_device[_]
    block.encrypted != true
    msg := sprintf(
        "SC-28 VIOLATION: EC2 instance '%s' root volume must be encrypted",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# SC-7: Boundary Protection - Security Groups
# -----------------------------------------------------------------------------

# Deny security groups with unrestricted SSH (0.0.0.0/0 on port 22)
deny_sg_unrestricted_ssh contains msg if {
    resources := resource_changes["aws_security_group"]
    r := resources[_]
    values := after_values(r)
    ingress := values.ingress[_]
    ingress.from_port <= 22
    ingress.to_port >= 22
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf(
        "SC-7 VIOLATION: Security group '%s' allows unrestricted SSH access (0.0.0.0/0)",
        [r.address]
    )
}

# Deny security groups with unrestricted RDP (0.0.0.0/0 on port 3389)
deny_sg_unrestricted_rdp contains msg if {
    resources := resource_changes["aws_security_group"]
    r := resources[_]
    values := after_values(r)
    ingress := values.ingress[_]
    ingress.from_port <= 3389
    ingress.to_port >= 3389
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf(
        "SC-7 VIOLATION: Security group '%s' allows unrestricted RDP access (0.0.0.0/0)",
        [r.address]
    )
}

# Deny security groups with unrestricted database ports
deny_sg_unrestricted_db contains msg if {
    resources := resource_changes["aws_security_group"]
    r := resources[_]
    values := after_values(r)
    ingress := values.ingress[_]
    db_port_exposed(ingress)
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf(
        "SC-7 VIOLATION: Security group '%s' allows unrestricted database access",
        [r.address]
    )
}

db_port_exposed(ingress) if {
    db_ports := [3306, 5432, 1433, 1521, 27017, 6379]  # MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis
    port := db_ports[_]
    ingress.from_port <= port
    ingress.to_port >= port
}

# Deny security groups allowing all egress
deny_sg_unrestricted_egress contains msg if {
    resources := resource_changes["aws_security_group"]
    r := resources[_]
    values := after_values(r)
    egress := values.egress[_]
    egress.from_port == 0
    egress.to_port == 0
    egress.protocol == "-1"
    cidr := egress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf(
        "SC-7 WARNING: Security group '%s' allows unrestricted egress - review for least privilege",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# SC-8: Transmission Confidentiality - TLS Enforcement
# -----------------------------------------------------------------------------

# Deny ALB listeners without HTTPS
deny_alb_no_https contains msg if {
    resources := resource_changes["aws_lb_listener"]
    r := resources[_]
    values := after_values(r)
    values.protocol == "HTTP"
    values.port != 80  # Allow HTTP redirect listeners
    msg := sprintf(
        "SC-8 VIOLATION: ALB listener '%s' must use HTTPS protocol",
        [r.address]
    )
}

# Deny ALB listeners with insecure SSL policies
deny_alb_insecure_ssl contains msg if {
    resources := resource_changes["aws_lb_listener"]
    r := resources[_]
    values := after_values(r)
    values.protocol == "HTTPS"
    not secure_ssl_policy(values.ssl_policy)
    msg := sprintf(
        "SC-8 VIOLATION: ALB listener '%s' must use TLS 1.2+ (current policy: %s)",
        [r.address, values.ssl_policy]
    )
}

secure_ssl_policy(policy) if {
    secure_policies := [
        "ELBSecurityPolicy-TLS13-1-2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08"
    ]
    policy in secure_policies
}

# -----------------------------------------------------------------------------
# AU-2: Event Logging - CloudTrail Validation
# -----------------------------------------------------------------------------

# Deny CloudTrail without log file validation
deny_cloudtrail_no_validation contains msg if {
    resources := resource_changes["aws_cloudtrail"]
    r := resources[_]
    values := after_values(r)
    values.enable_log_file_validation != true
    msg := sprintf(
        "AU-2 VIOLATION: CloudTrail '%s' must have log file validation enabled",
        [r.address]
    )
}

# Deny CloudTrail without encryption
deny_cloudtrail_no_encryption contains msg if {
    resources := resource_changes["aws_cloudtrail"]
    r := resources[_]
    values := after_values(r)
    not values.kms_key_id
    msg := sprintf(
        "SC-13 VIOLATION: CloudTrail '%s' must use KMS encryption",
        [r.address]
    )
}

# Deny CloudTrail without multi-region enabled
deny_cloudtrail_single_region contains msg if {
    resources := resource_changes["aws_cloudtrail"]
    r := resources[_]
    values := after_values(r)
    values.is_multi_region_trail != true
    msg := sprintf(
        "AU-2 VIOLATION: CloudTrail '%s' must be multi-region for FedRAMP High",
        [r.address]
    )
}

# Deny CloudTrail without CloudWatch integration
deny_cloudtrail_no_cloudwatch contains msg if {
    resources := resource_changes["aws_cloudtrail"]
    r := resources[_]
    values := after_values(r)
    not values.cloud_watch_logs_group_arn
    msg := sprintf(
        "AU-6 VIOLATION: CloudTrail '%s' must send logs to CloudWatch for real-time analysis",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# AU-9: Protection of Audit Information - Log Retention
# -----------------------------------------------------------------------------

# Deny CloudWatch log groups with insufficient retention
deny_logs_short_retention contains msg if {
    resources := resource_changes["aws_cloudwatch_log_group"]
    r := resources[_]
    values := after_values(r)
    values.retention_in_days < 365  # FedRAMP High requires 1+ year
    msg := sprintf(
        "AU-9 VIOLATION: CloudWatch log group '%s' retention must be at least 365 days (current: %d)",
        [r.address, values.retention_in_days]
    )
}

# Deny CloudWatch log groups without encryption
deny_logs_no_encryption contains msg if {
    resources := resource_changes["aws_cloudwatch_log_group"]
    r := resources[_]
    values := after_values(r)
    not values.kms_key_id
    msg := sprintf(
        "SC-13 VIOLATION: CloudWatch log group '%s' must use KMS encryption",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# AC-6: Least Privilege - IAM Policy Validation
# -----------------------------------------------------------------------------

# Deny IAM policies with wildcard actions
deny_iam_wildcard_actions contains msg if {
    resources := resource_changes["aws_iam_policy"]
    r := resources[_]
    values := after_values(r)
    policy := json.unmarshal(values.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    action := statement.Action[_]
    action == "*"
    msg := sprintf(
        "AC-6 VIOLATION: IAM policy '%s' contains wildcard actions - use least privilege",
        [r.address]
    )
}

# Deny IAM policies with wildcard resources (with * actions)
deny_iam_wildcard_resources contains msg if {
    resources := resource_changes["aws_iam_policy"]
    r := resources[_]
    values := after_values(r)
    policy := json.unmarshal(values.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Resource == "*"
    action := statement.Action[_]
    contains(action, "*")
    msg := sprintf(
        "AC-6 WARNING: IAM policy '%s' allows wildcard resources with broad actions - review for least privilege",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# CM-6: Configuration Settings - VPC Configuration
# -----------------------------------------------------------------------------

# Deny VPCs without flow logs
deny_vpc_no_flow_logs contains msg if {
    resources := resource_changes["aws_vpc"]
    r := resources[_]
    vpc_id := r.change.after.id
    not vpc_has_flow_log(r.address)
    msg := sprintf(
        "AU-2 VIOLATION: VPC '%s' must have flow logs enabled",
        [r.address]
    )
}

vpc_has_flow_log(vpc_address) if {
    resources := resource_changes["aws_flow_log"]
    count(resources) > 0
}

# Deny VPCs without DNS support
deny_vpc_no_dns contains msg if {
    resources := resource_changes["aws_vpc"]
    r := resources[_]
    values := after_values(r)
    values.enable_dns_support != true
    msg := sprintf(
        "CM-6 VIOLATION: VPC '%s' must have DNS support enabled",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# IA-5: Authenticator Management - Secrets Management
# -----------------------------------------------------------------------------

# Deny Secrets Manager secrets without rotation
deny_secrets_no_rotation contains msg if {
    resources := resource_changes["aws_secretsmanager_secret"]
    r := resources[_]
    not secret_has_rotation(r.address)
    msg := sprintf(
        "IA-5 WARNING: Secret '%s' should have automatic rotation configured",
        [r.address]
    )
}

secret_has_rotation(secret_address) if {
    resources := resource_changes["aws_secretsmanager_secret_rotation"]
    r := resources[_]
    contains(r.address, secret_address)
}

# Deny Secrets Manager secrets without encryption
deny_secrets_no_encryption contains msg if {
    resources := resource_changes["aws_secretsmanager_secret"]
    r := resources[_]
    values := after_values(r)
    not values.kms_key_id
    msg := sprintf(
        "SC-13 VIOLATION: Secret '%s' must use customer-managed KMS key",
        [r.address]
    )
}

# -----------------------------------------------------------------------------
# Aggregate all violations
# -----------------------------------------------------------------------------

violations := {
    "critical": critical_violations,
    "high": high_violations,
    "medium": medium_violations,
    "total_count": count(critical_violations) + count(high_violations) + count(medium_violations)
}

critical_violations := deny_kms_no_rotation |
    deny_s3_no_encryption |
    deny_rds_no_encryption |
    deny_ebs_no_encryption |
    deny_cloudtrail_no_validation |
    deny_cloudtrail_no_encryption

high_violations := deny_sg_unrestricted_ssh |
    deny_sg_unrestricted_rdp |
    deny_sg_unrestricted_db |
    deny_rds_publicly_accessible |
    deny_alb_no_https |
    deny_alb_insecure_ssl |
    deny_cloudtrail_single_region |
    deny_logs_short_retention |
    deny_logs_no_encryption |
    deny_iam_wildcard_actions

medium_violations := deny_s3_public_access |
    deny_s3_no_versioning |
    deny_rds_no_cmk |
    deny_kms_short_deletion |
    deny_cloudtrail_no_cloudwatch |
    deny_ec2_unencrypted_root |
    deny_vpc_no_dns |
    deny_secrets_no_encryption

# Final deny rule - fail if any critical violations
deny[msg] {
    msg := critical_violations[_]
}

deny[msg] {
    msg := high_violations[_]
}

# Warning rule - report but don't fail
warn[msg] {
    msg := medium_violations[_]
}
