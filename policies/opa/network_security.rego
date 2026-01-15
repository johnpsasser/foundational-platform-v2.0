# FedRAMP High / IL5 Network Security Policies
#
# This policy validates network security configurations required by
# FedRAMP High and DoD IL5 compliance:
#
# - No public ingress without explicit approval
# - No unrestricted egress without explicit approval
# - VPC flow logs must be enabled
# - Security groups must not allow 0.0.0.0/0 ingress
# - Private endpoints for AWS services

package fedramp.network

import future.keywords.contains
import future.keywords.if
import future.keywords.in

#------------------------------------------------------------------------------
# Security Group Rules - Ingress
#------------------------------------------------------------------------------

# Deny security groups with unrestricted ingress (0.0.0.0/0)
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] != "delete"

    resource.change.after.type == "ingress"
    cidr := resource.change.after.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    # Check if not explicitly approved
    not has_public_ingress_approval(resource)

    msg := sprintf(
        "Security group rule '%s' allows unrestricted ingress from 0.0.0.0/0. Public ingress requires explicit approval tag 'PublicIngressApproved=true' for IL5 compliance.",
        [resource.address]
    )
}

# Deny security groups with unrestricted IPv6 ingress
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] != "delete"

    resource.change.after.type == "ingress"
    cidr := resource.change.after.ipv6_cidr_blocks[_]
    cidr == "::/0"

    not has_public_ingress_approval(resource)

    msg := sprintf(
        "Security group rule '%s' allows unrestricted IPv6 ingress from ::/0. Public ingress requires explicit approval for IL5 compliance.",
        [resource.address]
    )
}

# Deny inline security group rules with unrestricted ingress
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    ingress := resource.change.after.ingress[_]
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    not has_public_ingress_approval(resource)

    msg := sprintf(
        "Security group '%s' has inline rule allowing unrestricted ingress from 0.0.0.0/0. Public ingress requires explicit approval for IL5 compliance.",
        [resource.address]
    )
}

# Deny SSH access from anywhere
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_security_group", "aws_security_group_rule"}
    resource.change.actions[_] != "delete"

    allows_port_from_anywhere(resource, 22)

    msg := sprintf(
        "Security group '%s' allows SSH (port 22) from 0.0.0.0/0. Direct SSH access from the internet is prohibited for IL5. Use SSM Session Manager or bastion hosts.",
        [resource.address]
    )
}

# Deny RDP access from anywhere
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_security_group", "aws_security_group_rule"}
    resource.change.actions[_] != "delete"

    allows_port_from_anywhere(resource, 3389)

    msg := sprintf(
        "Security group '%s' allows RDP (port 3389) from 0.0.0.0/0. Direct RDP access from the internet is prohibited for IL5.",
        [resource.address]
    )
}

# Helper: Check if resource has public ingress approval
has_public_ingress_approval(resource) if {
    resource.change.after.tags.PublicIngressApproved == "true"
}

# Helper: Check if allows specific port from anywhere
allows_port_from_anywhere(resource, port) if {
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    resource.change.after.from_port <= port
    resource.change.after.to_port >= port
    cidr := resource.change.after.cidr_blocks[_]
    cidr == "0.0.0.0/0"
}

allows_port_from_anywhere(resource, port) if {
    resource.type == "aws_security_group"
    ingress := resource.change.after.ingress[_]
    ingress.from_port <= port
    ingress.to_port >= port
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
}

#------------------------------------------------------------------------------
# Security Group Rules - Egress
#------------------------------------------------------------------------------

# Warn on unrestricted egress (0.0.0.0/0 on all ports)
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    egress := resource.change.after.egress[_]
    egress.from_port == 0
    egress.to_port == 0
    egress.protocol == "-1"
    cidr := egress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    not has_unrestricted_egress_approval(resource)

    msg := sprintf(
        "Security group '%s' allows unrestricted egress to 0.0.0.0/0 on all ports. Consider restricting egress for IL5 compliance.",
        [resource.address]
    )
}

# Helper: Check if unrestricted egress is approved
has_unrestricted_egress_approval(resource) if {
    resource.change.after.tags.UnrestrictedEgressApproved == "true"
}

#------------------------------------------------------------------------------
# VPC Flow Logs
#------------------------------------------------------------------------------

# Deny VPCs without flow logs
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    resource.change.actions[_] != "delete"

    vpc_id := resource.change.after_unknown.id
    not has_flow_log(vpc_id)

    msg := sprintf(
        "VPC '%s' does not have flow logs enabled. VPC flow logs are required for IL5 compliance.",
        [resource.address]
    )
}

# Helper: Check if VPC has flow log
has_flow_log(vpc_id) if {
    resource := input.resource_changes[_]
    resource.type == "aws_flow_log"
    resource.change.actions[_] != "delete"
}

# Deny flow logs with short retention
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] != "delete"

    # Check if this is a flow log group
    contains(resource.address, "flow")

    retention := resource.change.after.retention_in_days
    retention < 365

    msg := sprintf(
        "Flow log group '%s' has retention of %d days. IL5 requires minimum 365 days log retention.",
        [resource.address, retention]
    )
}

#------------------------------------------------------------------------------
# S3 Bucket Public Access
#------------------------------------------------------------------------------

# Deny S3 buckets without public access block
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    bucket_name := resource.change.after.bucket
    not has_public_access_block(bucket_name)

    msg := sprintf(
        "S3 bucket '%s' does not have public access block configured. All S3 buckets must block public access for IL5 compliance.",
        [resource.address]
    )
}

# Deny S3 public access blocks that don't block all public access
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.actions[_] != "delete"

    not resource.change.after.block_public_acls
    not resource.change.after.block_public_policy
    not resource.change.after.ignore_public_acls
    not resource.change.after.restrict_public_buckets

    msg := sprintf(
        "S3 public access block '%s' does not fully block public access. All four settings must be true for IL5 compliance.",
        [resource.address]
    )
}

# Helper: Check if S3 bucket has public access block
has_public_access_block(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.actions[_] != "delete"
    resource.change.after.bucket == bucket_name
}

#------------------------------------------------------------------------------
# EKS Cluster Network Configuration
#------------------------------------------------------------------------------

# Deny EKS clusters with public endpoint access
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    vpc_config := resource.change.after.vpc_config[_]
    vpc_config.endpoint_public_access == true
    not vpc_config.endpoint_private_access

    msg := sprintf(
        "EKS cluster '%s' has public endpoint access without private access. IL5 requires private endpoint access to be enabled.",
        [resource.address]
    )
}

# Warn on EKS clusters with public endpoint (even with private enabled)
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    vpc_config := resource.change.after.vpc_config[_]
    vpc_config.endpoint_public_access == true

    msg := sprintf(
        "EKS cluster '%s' has public endpoint access enabled. Consider disabling public access for IL5 compliance.",
        [resource.address]
    )
}

# Deny EKS clusters without private endpoint access
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] != "delete"

    vpc_config := resource.change.after.vpc_config[_]
    not vpc_config.endpoint_private_access

    msg := sprintf(
        "EKS cluster '%s' does not have private endpoint access enabled. Private endpoint access is required for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# RDS Public Accessibility
#------------------------------------------------------------------------------

# Deny publicly accessible RDS instances
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_db_instance", "aws_rds_cluster"}
    resource.change.actions[_] != "delete"

    resource.change.after.publicly_accessible == true

    msg := sprintf(
        "RDS resource '%s' is publicly accessible. Databases must not be publicly accessible for IL5 compliance.",
        [resource.address]
    )
}

#------------------------------------------------------------------------------
# ALB/ELB Configuration
#------------------------------------------------------------------------------

# Warn on internet-facing load balancers without WAF
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_lb", "aws_alb"}
    resource.change.actions[_] != "delete"

    resource.change.after.internal == false
    not has_waf_association(resource.address)

    msg := sprintf(
        "Load balancer '%s' is internet-facing but may not have WAF protection. Consider attaching AWS WAF for IL5 compliance.",
        [resource.address]
    )
}

# Deny load balancers without access logs
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type in {"aws_lb", "aws_alb"}
    resource.change.actions[_] != "delete"

    access_logs := resource.change.after.access_logs[_]
    not access_logs.enabled

    msg := sprintf(
        "Load balancer '%s' does not have access logs enabled. Access logs are required for IL5 compliance.",
        [resource.address]
    )
}

# Helper: Check for WAF association (simplified check)
has_waf_association(lb_address) if {
    resource := input.resource_changes[_]
    resource.type == "aws_wafv2_web_acl_association"
    resource.change.actions[_] != "delete"
}

#------------------------------------------------------------------------------
# Network ACL Rules
#------------------------------------------------------------------------------

# Warn on NACLs with allow all inbound
warn[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_network_acl_rule"
    resource.change.actions[_] != "delete"

    resource.change.after.egress == false
    resource.change.after.rule_action == "allow"
    resource.change.after.cidr_block == "0.0.0.0/0"
    resource.change.after.protocol == "-1"

    msg := sprintf(
        "Network ACL rule '%s' allows all inbound traffic from 0.0.0.0/0. Review for IL5 compliance.",
        [resource.address]
    )
}
