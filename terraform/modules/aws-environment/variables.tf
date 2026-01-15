#------------------------------------------------------------------------------
# Environment Contract Interface - AWS Implementation
#
# This file defines the standardized input variables that abstract cloud
# differences. The same variable interface is used across AWS, Azure, and
# on-prem (K3s) implementations to ensure portability.
#
# Classification: IL4-IL5 / FedRAMP High
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Core Environment Configuration
#------------------------------------------------------------------------------

variable "environment_name" {
  description = "Name of the environment (e.g., production, staging, development)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment_name))
    error_message = "Environment name must be lowercase alphanumeric with hyphens only."
  }
}

variable "environment_type" {
  description = "Type of environment for compliance classification"
  type        = string

  validation {
    condition     = contains(["production", "staging", "development", "disaster-recovery"], var.environment_type)
    error_message = "Environment type must be one of: production, staging, development, disaster-recovery."
  }
}

variable "classification_level" {
  description = "Data classification level (IL4, IL5, IL6)"
  type        = string
  default     = "IL5"

  validation {
    condition     = contains(["IL4", "IL5", "IL6"], var.classification_level)
    error_message = "Classification level must be IL4, IL5, or IL6."
  }
}

variable "region" {
  description = "AWS region identifier"
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.region))
    error_message = "Region must follow AWS format (e.g., us-east-1, us-gov-west-1)."
  }
}

#------------------------------------------------------------------------------
# Required Tags (Policy-as-Code Enforced)
#------------------------------------------------------------------------------

variable "required_tags" {
  description = "Required tags for all resources - enforced by OPA policies"
  type = object({
    Owner          = string
    Environment    = string
    Classification = string
    CostCenter     = string
    DataSensitivity = string
    Compliance     = string
  })

  validation {
    condition     = contains(["IL4", "IL5", "IL6"], var.required_tags.Classification)
    error_message = "Classification tag must be IL4, IL5, or IL6."
  }

  validation {
    condition     = contains(["FedRAMP-High", "FedRAMP-Moderate", "DoD-IL4", "DoD-IL5"], var.required_tags.Compliance)
    error_message = "Compliance tag must be one of: FedRAMP-High, FedRAMP-Moderate, DoD-IL4, DoD-IL5."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

#------------------------------------------------------------------------------
# Network Abstraction Layer
#------------------------------------------------------------------------------

variable "network_config" {
  description = "Cloud-agnostic network configuration"
  type = object({
    # Primary network CIDR (VPC in AWS, VNet in Azure)
    cidr_block = string

    # Availability zones / fault domains count
    availability_zone_count = number

    # Subnet tier configuration
    subnet_tiers = object({
      public = object({
        enabled     = bool
        cidr_bits   = number  # Bits to add to CIDR for subnet calculation
        nat_gateway = bool    # Enable NAT gateway/NAT instance
      })
      private = object({
        enabled   = bool
        cidr_bits = number
      })
      isolated = object({
        enabled   = bool
        cidr_bits = number
      })
      data = object({
        enabled   = bool
        cidr_bits = number
      })
    })

    # DNS configuration
    dns_config = object({
      enable_dns_hostnames = bool
      enable_dns_support   = bool
      private_zone_name    = string
    })

    # Flow logs configuration (required for IL5)
    flow_logs = object({
      enabled         = bool
      retention_days  = number
      traffic_type    = string  # ALL, ACCEPT, REJECT
    })
  })

  validation {
    condition     = can(cidrhost(var.network_config.cidr_block, 0))
    error_message = "Network CIDR block must be a valid IPv4 CIDR."
  }

  validation {
    condition     = var.network_config.availability_zone_count >= 2
    error_message = "At least 2 availability zones required for high availability."
  }

  validation {
    condition     = var.network_config.flow_logs.enabled == true
    error_message = "Flow logs must be enabled for IL4+ compliance."
  }
}

#------------------------------------------------------------------------------
# Kubernetes Cluster Abstraction
#------------------------------------------------------------------------------

variable "kubernetes_config" {
  description = "Cloud-agnostic Kubernetes cluster configuration"
  type = object({
    # Cluster identification
    cluster_name    = string
    cluster_version = string

    # Control plane configuration
    control_plane = object({
      endpoint_private_access = bool  # Required true for IL5
      endpoint_public_access  = bool  # Required false for IL5

      # Logging configuration
      logging = object({
        api_server         = bool
        audit              = bool
        authenticator      = bool
        controller_manager = bool
        scheduler          = bool
      })
    })

    # Node group configuration (abstracted from managed/self-managed)
    node_groups = map(object({
      name           = string
      instance_type  = string  # Mapped to cloud-specific types
      min_size       = number
      max_size       = number
      desired_size   = number
      disk_size_gb   = number
      disk_encrypted = bool    # Required true for IL5

      # Node placement
      subnet_tier    = string  # public, private, isolated, data

      # Taints and labels
      labels = map(string)
      taints = list(object({
        key    = string
        value  = string
        effect = string
      }))
    }))

    # Add-ons configuration
    addons = object({
      vpc_cni            = bool
      coredns            = bool
      kube_proxy         = bool
      ebs_csi_driver     = bool
      efs_csi_driver     = bool
      secrets_store_csi  = bool
    })

    # OIDC configuration for IAM integration
    enable_irsa = bool  # IAM Roles for Service Accounts (AWS) / Workload Identity (Azure)
  })

  validation {
    condition     = var.kubernetes_config.control_plane.endpoint_private_access == true
    error_message = "Private endpoint access must be enabled for IL5 compliance."
  }

  validation {
    condition     = var.kubernetes_config.control_plane.logging.audit == true
    error_message = "Audit logging must be enabled for IL5 compliance."
  }
}

#------------------------------------------------------------------------------
# Identity and Access Management Abstraction
#------------------------------------------------------------------------------

variable "iam_config" {
  description = "Cloud-agnostic IAM configuration"
  type = object({
    # Service account / managed identity configuration
    service_accounts = map(object({
      name        = string
      namespace   = string
      description = string

      # Cloud-agnostic policy definitions (mapped to IAM/RBAC)
      permissions = list(object({
        service    = string   # e.g., "storage", "secrets", "database"
        actions    = list(string)
        resources  = list(string)
        conditions = map(string)
      }))
    }))

    # Cross-account / cross-subscription trust
    trusted_principals = list(object({
      type       = string  # "account", "service", "federated"
      identifier = string
      conditions = map(string)
    }))

    # MFA and session configuration
    require_mfa         = bool
    max_session_duration = number
  })

  validation {
    condition     = var.iam_config.require_mfa == true
    error_message = "MFA must be required for IL5 compliance."
  }
}

#------------------------------------------------------------------------------
# Encryption and Key Management Abstraction
#------------------------------------------------------------------------------

variable "kms_config" {
  description = "Cloud-agnostic encryption and key management configuration"
  type = object({
    # Customer-managed key configuration
    customer_managed_keys = map(object({
      name                 = string
      description          = string
      key_usage            = string  # ENCRYPT_DECRYPT, SIGN_VERIFY
      key_spec             = string  # SYMMETRIC_DEFAULT, RSA_2048, etc.

      # Rotation configuration
      enable_rotation      = bool
      rotation_period_days = number

      # Key policy principals
      key_administrators   = list(string)
      key_users           = list(string)

      # Deletion protection
      deletion_window_days = number
      enable_key_deletion  = bool
    }))

    # Default encryption key for general use
    default_key_alias = string

    # HSM backing (required for IL5)
    use_hsm_backing = bool
  })

  validation {
    condition     = var.kms_config.use_hsm_backing == true
    error_message = "HSM backing must be enabled for IL5 compliance."
  }

  validation {
    condition = alltrue([
      for key in var.kms_config.customer_managed_keys : key.enable_rotation == true
    ])
    error_message = "All customer-managed keys must have rotation enabled."
  }
}

#------------------------------------------------------------------------------
# Private Endpoints / PrivateLink Configuration
#------------------------------------------------------------------------------

variable "private_endpoints" {
  description = "Cloud-agnostic private endpoint configuration for platform services"
  type = object({
    enabled = bool

    # Services to enable private endpoints for
    services = object({
      container_registry = bool
      secrets_manager    = bool
      key_management     = bool
      storage            = bool
      database           = bool
      monitoring         = bool
      logging            = bool
    })

    # DNS configuration for private endpoints
    private_dns_enabled = bool
  })

  validation {
    condition     = var.private_endpoints.enabled == true
    error_message = "Private endpoints must be enabled for IL5 compliance."
  }
}

#------------------------------------------------------------------------------
# Logging and Monitoring Configuration
#------------------------------------------------------------------------------

variable "logging_config" {
  description = "Cloud-agnostic logging and monitoring configuration"
  type = object({
    # Centralized logging
    centralized_logging = object({
      enabled           = bool
      retention_days    = number
      encryption_key_id = string  # Reference to KMS key
    })

    # Audit logging
    audit_logging = object({
      enabled              = bool
      include_management   = bool
      include_data_events  = bool
      include_read_only    = bool
    })

    # Metrics and alerting
    metrics = object({
      enabled            = bool
      detailed_monitoring = bool
      retention_days     = number
    })

    # Security event logging
    security_logging = object({
      enabled              = bool
      threat_detection     = bool
      vulnerability_scanning = bool
    })
  })

  validation {
    condition     = var.logging_config.centralized_logging.enabled == true
    error_message = "Centralized logging must be enabled for IL5 compliance."
  }

  validation {
    condition     = var.logging_config.audit_logging.enabled == true
    error_message = "Audit logging must be enabled for IL5 compliance."
  }

  validation {
    condition     = var.logging_config.centralized_logging.retention_days >= 365
    error_message = "Log retention must be at least 365 days for IL5 compliance."
  }
}

#------------------------------------------------------------------------------
# Transit / Connectivity Configuration
#------------------------------------------------------------------------------

variable "transit_config" {
  description = "Multi-VPC/VNet connectivity configuration"
  type = object({
    # Transit gateway / virtual WAN
    enable_transit_gateway = bool

    # VPC/VNet attachments
    transit_attachments = list(object({
      name       = string
      cidr_block = string
      route_tables = list(string)
    }))

    # Direct Connect / ExpressRoute
    dedicated_connection = object({
      enabled     = bool
      bandwidth   = string
      location    = string
    })

    # VPN backup
    vpn_backup = object({
      enabled = bool
      type    = string  # site-to-site, client
    })
  })
}

#------------------------------------------------------------------------------
# Backup and Disaster Recovery
#------------------------------------------------------------------------------

variable "backup_config" {
  description = "Backup and disaster recovery configuration"
  type = object({
    # Backup vault configuration
    backup_vault = object({
      enabled         = bool
      encryption_key  = string
      retention_days  = number
    })

    # Cross-region replication
    cross_region_replication = object({
      enabled           = bool
      destination_region = string
    })

    # Point-in-time recovery
    point_in_time_recovery = object({
      enabled         = bool
      retention_days  = number
    })
  })

  validation {
    condition     = var.backup_config.backup_vault.enabled == true
    error_message = "Backup vault must be enabled for IL5 compliance."
  }

  validation {
    condition     = var.backup_config.backup_vault.retention_days >= 90
    error_message = "Backup retention must be at least 90 days for IL5 compliance."
  }
}
