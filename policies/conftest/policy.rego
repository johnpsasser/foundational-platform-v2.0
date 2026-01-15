# Conftest Policy for Terraform Plan Validation
#
# This policy validates Terraform plan JSON output against FedRAMP High / IL5 requirements.
#
# Usage:
#   terraform plan -out=tfplan
#   terraform show -json tfplan > tfplan.json
#   conftest test tfplan.json -p policies/conftest/

package main

import rego.v1

#------------------------------------------------------------------------------
# Required Tags Policy
#------------------------------------------------------------------------------

required_tags := {"Owner", "Environment", "Classification", "CostCenter", "Compliance"}
valid_classifications := {"IL4", "IL5", "IL6"}
valid_compliance_values := {"FedRAMP-High", "FedRAMP-Moderate", "DoD-IL4", "DoD-IL5"}

# Helper to get tags from planned_values structure
get_tags(resource) := tags if {
    tags := resource.values.tags
} else := {}

# Helper to check if resource type should have tags
is_taggable(type) if {
    taggable_types := {
        "aws_vpc", "aws_subnet", "aws_security_group", "aws_s3_bucket",
        "aws_ebs_volume", "aws_kms_key", "aws_eks_cluster", "aws_db_instance",
        "aws_cloudtrail", "aws_guardduty_detector", "aws_cloudwatch_log_group",
        "aws_iam_role", "aws_lambda_function", "aws_rds_cluster"
    }
    type in taggable_types
}

# Deny: Missing required tags
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    is_taggable(resource.type)
    tags := get_tags(resource)
    missing := required_tags - {tag | some tag, _ in tags}
    count(missing) > 0
    msg := sprintf("[TAG-001] Resource '%s' (%s) missing required tags: %v", [resource.address, resource.type, missing])
}

# Deny: Missing required tags (in child modules)
deny contains msg if {
    some module in input.planned_values.root_module.child_modules
    some resource in module.resources
    is_taggable(resource.type)
    tags := get_tags(resource)
    missing := required_tags - {tag | some tag, _ in tags}
    count(missing) > 0
    msg := sprintf("[TAG-001] Resource '%s' (%s) missing required tags: %v", [resource.address, resource.type, missing])
}

# Deny: Invalid Classification value
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    is_taggable(resource.type)
    tags := get_tags(resource)
    classification := tags.Classification
    not classification in valid_classifications
    msg := sprintf("[TAG-002] Resource '%s' has invalid Classification '%s'. Must be one of: %v", [resource.address, classification, valid_classifications])
}

#------------------------------------------------------------------------------
# Encryption Policy
#------------------------------------------------------------------------------

# Deny: Unencrypted EBS volumes
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_ebs_volume"
    not resource.values.encrypted
    msg := sprintf("[ENC-001] EBS volume '%s' must be encrypted", [resource.address])
}

# Deny: Unencrypted RDS instances
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_db_instance"
    not resource.values.storage_encrypted
    msg := sprintf("[ENC-002] RDS instance '%s' must have storage_encrypted = true", [resource.address])
}

# Deny: KMS key without rotation
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_kms_key"
    not resource.values.enable_key_rotation
    msg := sprintf("[ENC-003] KMS key '%s' must have enable_key_rotation = true", [resource.address])
}

# Deny: EKS without secrets encryption
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_eks_cluster"
    not resource.values.encryption_config
    msg := sprintf("[ENC-004] EKS cluster '%s' must have encryption_config for secrets", [resource.address])
}

#------------------------------------------------------------------------------
# Network Security Policy
#------------------------------------------------------------------------------

# Deny: Security group with SSH from 0.0.0.0/0
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_security_group"
    some ingress in resource.values.ingress
    ingress.from_port <= 22
    ingress.to_port >= 22
    some cidr in ingress.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("[NET-001] Security group '%s' allows SSH from 0.0.0.0/0", [resource.address])
}

# Deny: Publicly accessible RDS
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_db_instance"
    resource.values.publicly_accessible == true
    msg := sprintf("[NET-003] RDS instance '%s' must not be publicly accessible", [resource.address])
}

# Deny: EKS without private endpoint
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_eks_cluster"
    some vpc_config in resource.values.vpc_config
    vpc_config.endpoint_public_access == true
    vpc_config.endpoint_private_access == false
    msg := sprintf("[NET-004] EKS cluster '%s' must have private endpoint access enabled", [resource.address])
}

#------------------------------------------------------------------------------
# Logging Policy
#------------------------------------------------------------------------------

# Deny: CloudTrail disabled
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_cloudtrail"
    resource.values.enable_logging == false
    msg := sprintf("[LOG-001] CloudTrail '%s' must have enable_logging = true", [resource.address])
}

# Deny: CloudTrail without encryption
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_cloudtrail"
    not resource.values.kms_key_id
    msg := sprintf("[LOG-002] CloudTrail '%s' must be encrypted with KMS", [resource.address])
}

# Deny: GuardDuty disabled
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_guardduty_detector"
    resource.values.enable == false
    msg := sprintf("[LOG-003] GuardDuty detector '%s' must be enabled", [resource.address])
}

# Deny: EKS without audit logging
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_eks_cluster"
    log_types := resource.values.enabled_cluster_log_types
    count(log_types) == 0
    msg := sprintf("[LOG-004] EKS cluster '%s' must have audit logging enabled", [resource.address])
}

# Deny: Insufficient log retention
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_cloudwatch_log_group"
    resource.values.retention_in_days < 365
    msg := sprintf("[LOG-005] CloudWatch Log Group '%s' must have retention >= 365 days (has %d)", [resource.address, resource.values.retention_in_days])
}
