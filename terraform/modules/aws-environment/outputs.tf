#------------------------------------------------------------------------------
# Environment Contract Interface - Outputs
#
# These outputs provide a standardized interface for consuming the environment
# module, regardless of the underlying cloud provider.
#
# Classification: IL4-IL5 / FedRAMP High
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Network Outputs
#------------------------------------------------------------------------------

output "network" {
  description = "Network configuration outputs (VPC/VNet abstraction)"
  value = {
    # Network identifier
    network_id   = aws_vpc.main.id
    network_arn  = aws_vpc.main.arn
    network_cidr = aws_vpc.main.cidr_block

    # Subnet outputs by tier
    subnets = {
      public = {
        ids   = aws_subnet.public[*].id
        arns  = aws_subnet.public[*].arn
        cidrs = aws_subnet.public[*].cidr_block
        azs   = aws_subnet.public[*].availability_zone
      }
      private = {
        ids   = aws_subnet.private[*].id
        arns  = aws_subnet.private[*].arn
        cidrs = aws_subnet.private[*].cidr_block
        azs   = aws_subnet.private[*].availability_zone
      }
      isolated = {
        ids   = aws_subnet.isolated[*].id
        arns  = aws_subnet.isolated[*].arn
        cidrs = aws_subnet.isolated[*].cidr_block
        azs   = aws_subnet.isolated[*].availability_zone
      }
      data = {
        ids   = aws_subnet.data[*].id
        arns  = aws_subnet.data[*].arn
        cidrs = aws_subnet.data[*].cidr_block
        azs   = aws_subnet.data[*].availability_zone
      }
    }

    # Route tables
    route_tables = {
      public_ids   = aws_route_table.public[*].id
      private_ids  = aws_route_table.private[*].id
      isolated_ids = aws_route_table.isolated[*].id
      data_ids     = aws_route_table.data[*].id
    }

    # NAT Gateways
    nat_gateway_ids = aws_nat_gateway.main[*].id

    # Internet Gateway (if public tier enabled)
    internet_gateway_id = var.network_config.subnet_tiers.public.enabled ? aws_internet_gateway.main[0].id : null

    # Private DNS zone
    private_dns_zone_id   = aws_route53_zone.private.zone_id
    private_dns_zone_name = aws_route53_zone.private.name
  }
}

output "network_security" {
  description = "Network security group outputs"
  value = {
    # Default security groups by tier
    security_groups = {
      bastion_sg_id  = aws_security_group.bastion.id
      cluster_sg_id  = aws_security_group.cluster.id
      node_sg_id     = aws_security_group.node.id
      data_sg_id     = aws_security_group.data.id
      endpoint_sg_id = aws_security_group.endpoints.id
    }

    # Network ACLs
    network_acls = {
      public_nacl_id   = aws_network_acl.public.id
      private_nacl_id  = aws_network_acl.private.id
      isolated_nacl_id = aws_network_acl.isolated.id
      data_nacl_id     = aws_network_acl.data.id
    }

    # Flow logs
    flow_log_id           = aws_flow_log.main.id
    flow_log_group_arn    = aws_cloudwatch_log_group.flow_logs.arn
  }
}

#------------------------------------------------------------------------------
# Kubernetes Cluster Outputs
#------------------------------------------------------------------------------

output "kubernetes" {
  description = "Kubernetes cluster outputs (EKS/AKS/K3s abstraction)"
  value = {
    # Cluster identification
    cluster_id       = aws_eks_cluster.main.id
    cluster_name     = aws_eks_cluster.main.name
    cluster_arn      = aws_eks_cluster.main.arn
    cluster_version  = aws_eks_cluster.main.version

    # Cluster endpoints
    cluster_endpoint                   = aws_eks_cluster.main.endpoint
    cluster_certificate_authority_data = aws_eks_cluster.main.certificate_authority[0].data

    # OIDC configuration for workload identity
    oidc_provider_arn = try(aws_iam_openid_connect_provider.eks[0].arn, null)
    oidc_provider_url = aws_eks_cluster.main.identity[0].oidc[0].issuer

    # Node groups
    node_groups = {
      for ng_key, ng in aws_eks_node_group.main : ng_key => {
        id            = ng.id
        arn           = ng.arn
        status        = ng.status
        capacity_type = ng.capacity_type
        scaling_config = {
          min_size     = ng.scaling_config[0].min_size
          max_size     = ng.scaling_config[0].max_size
          desired_size = ng.scaling_config[0].desired_size
        }
      }
    }

    # Security
    cluster_security_group_id = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id

    # Add-ons
    addons = {
      for addon_key, addon in aws_eks_addon.main : addon_key => {
        name    = addon.addon_name
        version = addon.addon_version
        status  = addon.status
      }
    }
  }

  sensitive = true
}

#------------------------------------------------------------------------------
# Identity and Access Management Outputs
#------------------------------------------------------------------------------

output "iam" {
  description = "IAM configuration outputs"
  value = {
    # Cluster role
    cluster_role_arn  = aws_iam_role.cluster.arn
    cluster_role_name = aws_iam_role.cluster.name

    # Node role
    node_role_arn  = aws_iam_role.node.arn
    node_role_name = aws_iam_role.node.name

    # Service account roles (IRSA)
    service_account_roles = {
      for sa_key, sa_role in aws_iam_role.service_account : sa_key => {
        role_arn  = sa_role.arn
        role_name = sa_role.name
      }
    }

    # Instance profiles
    node_instance_profile_arn  = aws_iam_instance_profile.node.arn
    node_instance_profile_name = aws_iam_instance_profile.node.name
  }
}

#------------------------------------------------------------------------------
# Key Management Service Outputs
#------------------------------------------------------------------------------

output "kms" {
  description = "KMS encryption key outputs"
  value = {
    # Customer-managed keys
    keys = {
      for key_name, key in aws_kms_key.main : key_name => {
        key_id    = key.key_id
        key_arn   = key.arn
        alias_arn = aws_kms_alias.main[key_name].arn
        alias_name = aws_kms_alias.main[key_name].name
      }
    }

    # Default encryption key
    default_key_arn   = aws_kms_key.main[var.kms_config.default_key_alias].arn
    default_key_id    = aws_kms_key.main[var.kms_config.default_key_alias].key_id
    default_alias_arn = aws_kms_alias.main[var.kms_config.default_key_alias].arn
  }
}

#------------------------------------------------------------------------------
# Private Endpoints Outputs
#------------------------------------------------------------------------------

output "private_endpoints" {
  description = "Private endpoint / PrivateLink outputs"
  value = {
    # VPC endpoints
    endpoints = {
      ecr_api = var.private_endpoints.services.container_registry ? {
        id          = aws_vpc_endpoint.ecr_api[0].id
        dns_entries = aws_vpc_endpoint.ecr_api[0].dns_entry
      } : null

      ecr_dkr = var.private_endpoints.services.container_registry ? {
        id          = aws_vpc_endpoint.ecr_dkr[0].id
        dns_entries = aws_vpc_endpoint.ecr_dkr[0].dns_entry
      } : null

      secrets_manager = var.private_endpoints.services.secrets_manager ? {
        id          = aws_vpc_endpoint.secretsmanager[0].id
        dns_entries = aws_vpc_endpoint.secretsmanager[0].dns_entry
      } : null

      kms = var.private_endpoints.services.key_management ? {
        id          = aws_vpc_endpoint.kms[0].id
        dns_entries = aws_vpc_endpoint.kms[0].dns_entry
      } : null

      s3 = var.private_endpoints.services.storage ? {
        id          = aws_vpc_endpoint.s3[0].id
        prefix_list = aws_vpc_endpoint.s3[0].prefix_list_id
      } : null

      logs = var.private_endpoints.services.logging ? {
        id          = aws_vpc_endpoint.logs[0].id
        dns_entries = aws_vpc_endpoint.logs[0].dns_entry
      } : null

      monitoring = var.private_endpoints.services.monitoring ? {
        id          = aws_vpc_endpoint.monitoring[0].id
        dns_entries = aws_vpc_endpoint.monitoring[0].dns_entry
      } : null

      sts = {
        id          = aws_vpc_endpoint.sts.id
        dns_entries = aws_vpc_endpoint.sts.dns_entry
      }

      ec2 = {
        id          = aws_vpc_endpoint.ec2.id
        dns_entries = aws_vpc_endpoint.ec2.dns_entry
      }

      autoscaling = {
        id          = aws_vpc_endpoint.autoscaling.id
        dns_entries = aws_vpc_endpoint.autoscaling.dns_entry
      }
    }
  }
}

#------------------------------------------------------------------------------
# Logging and Monitoring Outputs
#------------------------------------------------------------------------------

output "logging" {
  description = "Logging and monitoring outputs"
  value = {
    # CloudWatch Log Groups
    log_groups = {
      cluster_logs     = aws_cloudwatch_log_group.cluster.arn
      flow_logs        = aws_cloudwatch_log_group.flow_logs.arn
      application_logs = aws_cloudwatch_log_group.application.arn
      audit_logs       = aws_cloudwatch_log_group.audit.arn
    }

    # CloudTrail
    cloudtrail = {
      trail_arn    = aws_cloudtrail.main.arn
      trail_name   = aws_cloudtrail.main.name
      s3_bucket_id = aws_s3_bucket.cloudtrail.id
    }

    # GuardDuty
    guardduty_detector_id = aws_guardduty_detector.main.id

    # Security Hub
    security_hub_arn = aws_securityhub_account.main.id

    # Config
    config_recorder_id = aws_config_configuration_recorder.main.id
  }
}

#------------------------------------------------------------------------------
# Transit Connectivity Outputs
#------------------------------------------------------------------------------

output "transit" {
  description = "Transit connectivity outputs"
  value = var.transit_config.enable_transit_gateway ? {
    transit_gateway_id  = aws_ec2_transit_gateway.main[0].id
    transit_gateway_arn = aws_ec2_transit_gateway.main[0].arn

    attachments = {
      for att_key, att in aws_ec2_transit_gateway_vpc_attachment.main : att_key => {
        id     = att.id
        vpc_id = att.vpc_id
      }
    }

    route_table_ids = {
      for rt_key, rt in aws_ec2_transit_gateway_route_table.main : rt_key => rt.id
    }
  } : null
}

#------------------------------------------------------------------------------
# Backup Outputs
#------------------------------------------------------------------------------

output "backup" {
  description = "Backup and disaster recovery outputs"
  value = {
    backup_vault_arn  = aws_backup_vault.main.arn
    backup_vault_name = aws_backup_vault.main.name
    backup_plan_arn   = aws_backup_plan.main.arn
    backup_plan_id    = aws_backup_plan.main.id
  }
}

#------------------------------------------------------------------------------
# Environment Summary
#------------------------------------------------------------------------------

output "environment_summary" {
  description = "Summary of the deployed environment for documentation"
  value = {
    environment_name     = var.environment_name
    environment_type     = var.environment_type
    classification_level = var.classification_level
    region              = var.region
    cloud_provider      = "aws"

    compliance = {
      flow_logs_enabled     = var.network_config.flow_logs.enabled
      audit_logging_enabled = var.logging_config.audit_logging.enabled
      encryption_enabled    = true
      private_endpoints     = var.private_endpoints.enabled
      hsm_backed_keys       = var.kms_config.use_hsm_backing
    }

    tags = merge(
      {
        Owner          = var.required_tags.Owner
        Environment    = var.required_tags.Environment
        Classification = var.required_tags.Classification
        CostCenter     = var.required_tags.CostCenter
        Compliance     = var.required_tags.Compliance
      },
      var.additional_tags
    )
  }
}
