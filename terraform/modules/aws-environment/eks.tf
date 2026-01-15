#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - EKS Configuration
#
# Amazon EKS cluster configuration for FedRAMP High / IL4-IL5 compliance.
# Includes managed node groups, IRSA, and all required add-ons.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# EKS Cluster
#------------------------------------------------------------------------------

resource "aws_eks_cluster" "main" {
  name     = var.kubernetes_config.cluster_name
  version  = var.kubernetes_config.cluster_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids = concat(
      var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : [],
      var.network_config.subnet_tiers.isolated.enabled ? aws_subnet.isolated[*].id : []
    )

    endpoint_private_access = var.kubernetes_config.control_plane.endpoint_private_access
    endpoint_public_access  = var.kubernetes_config.control_plane.endpoint_public_access

    security_group_ids = [aws_security_group.cluster.id]
  }

  # Kubernetes secrets encryption with CMK
  encryption_config {
    provider {
      key_arn = aws_kms_key.main[var.kms_config.default_key_alias].arn
    }
    resources = ["secrets"]
  }

  # Control plane logging
  enabled_cluster_log_types = compact([
    var.kubernetes_config.control_plane.logging.api_server ? "api" : "",
    var.kubernetes_config.control_plane.logging.audit ? "audit" : "",
    var.kubernetes_config.control_plane.logging.authenticator ? "authenticator" : "",
    var.kubernetes_config.control_plane.logging.controller_manager ? "controllerManager" : "",
    var.kubernetes_config.control_plane.logging.scheduler ? "scheduler" : ""
  ])

  tags = merge(local.common_tags, {
    Name = var.kubernetes_config.cluster_name
  })

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.cluster_vpc_controller,
    aws_cloudwatch_log_group.cluster
  ]
}

#------------------------------------------------------------------------------
# EKS Cluster Log Group
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.kubernetes_config.cluster_name}/cluster"
  retention_in_days = var.logging_config.centralized_logging.retention_days
  kms_key_id        = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-cluster-logs"
  })
}

#------------------------------------------------------------------------------
# OIDC Provider for IRSA
#------------------------------------------------------------------------------

data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  count = var.kubernetes_config.enable_irsa ? 1 : 0

  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-oidc"
  })
}

#------------------------------------------------------------------------------
# EKS Managed Node Groups
#------------------------------------------------------------------------------

resource "aws_eks_node_group" "main" {
  for_each = var.kubernetes_config.node_groups

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.value.name
  node_role_arn   = aws_iam_role.node.arn
  version         = var.kubernetes_config.cluster_version

  # Subnet placement based on tier
  subnet_ids = lookup({
    "public"   = var.network_config.subnet_tiers.public.enabled ? aws_subnet.public[*].id : [],
    "private"  = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : [],
    "isolated" = var.network_config.subnet_tiers.isolated.enabled ? aws_subnet.isolated[*].id : [],
    "data"     = var.network_config.subnet_tiers.data.enabled ? aws_subnet.data[*].id : []
  }, each.value.subnet_tier, aws_subnet.private[*].id)

  # Instance configuration
  instance_types = [local.instance_type_map[each.value.instance_type]]
  capacity_type  = "ON_DEMAND"  # Required for IL5 - no spot instances

  # Scaling configuration
  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  # Disk configuration (encrypted)
  disk_size = each.value.disk_size_gb

  # Launch template for additional configuration
  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  # Labels
  labels = merge(
    each.value.labels,
    {
      "node-group"            = each.value.name
      "kubernetes.io/os"      = "linux"
      "node.kubernetes.io/instance-type" = each.value.instance_type
    }
  )

  # Taints
  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  # Update configuration
  update_config {
    max_unavailable_percentage = 25
  }

  tags = merge(local.common_tags, {
    Name                                           = "${var.kubernetes_config.cluster_name}-${each.value.name}"
    "kubernetes.io/cluster/${var.kubernetes_config.cluster_name}" = "owned"
  })

  depends_on = [
    aws_iam_role_policy_attachment.node_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_container_registry
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

#------------------------------------------------------------------------------
# Launch Template for Node Groups
#------------------------------------------------------------------------------

resource "aws_launch_template" "node" {
  for_each = var.kubernetes_config.node_groups

  name_prefix = "${var.kubernetes_config.cluster_name}-${each.value.name}-"
  description = "Launch template for EKS node group ${each.value.name}"

  # Block device mappings with encryption
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = each.value.disk_size_gb
      volume_type           = "gp3"
      encrypted             = true  # Required for IL5
      kms_key_id            = aws_kms_key.main[var.kms_config.default_key_alias].arn
      delete_on_termination = true
    }
  }

  # Metadata options (IMDSv2 required for IL5)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Monitoring
  monitoring {
    enabled = var.logging_config.metrics.detailed_monitoring
  }

  # Security
  vpc_security_group_ids = [aws_security_group.node.id]

  # User data for node configuration
  user_data = base64encode(templatefile("${path.module}/templates/node-userdata.sh.tpl", {
    cluster_name        = var.kubernetes_config.cluster_name
    cluster_endpoint    = aws_eks_cluster.main.endpoint
    cluster_ca          = aws_eks_cluster.main.certificate_authority[0].data
    node_labels         = join(",", [for k, v in each.value.labels : "${k}=${v}"])
    kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=normal"
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${var.kubernetes_config.cluster_name}-${each.value.name}"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name      = "${var.kubernetes_config.cluster_name}-${each.value.name}-volume"
      Encrypted = "true"
    })
  }

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-${each.value.name}-lt"
  })

  lifecycle {
    create_before_destroy = true
  }
}

#------------------------------------------------------------------------------
# Instance Type Mapping (cloud-agnostic to AWS)
#------------------------------------------------------------------------------

locals {
  instance_type_map = {
    # General purpose (mapped from cloud-agnostic names)
    "small"       = "m5.large"
    "medium"      = "m5.xlarge"
    "large"       = "m5.2xlarge"
    "xlarge"      = "m5.4xlarge"

    # Compute optimized
    "compute-small"  = "c5.large"
    "compute-medium" = "c5.xlarge"
    "compute-large"  = "c5.2xlarge"

    # Memory optimized
    "memory-small"  = "r5.large"
    "memory-medium" = "r5.xlarge"
    "memory-large"  = "r5.2xlarge"

    # Allow direct AWS instance types
    "m5.large"    = "m5.large"
    "m5.xlarge"   = "m5.xlarge"
    "m5.2xlarge"  = "m5.2xlarge"
    "m5.4xlarge"  = "m5.4xlarge"
    "c5.large"    = "c5.large"
    "c5.xlarge"   = "c5.xlarge"
    "c5.2xlarge"  = "c5.2xlarge"
    "r5.large"    = "r5.large"
    "r5.xlarge"   = "r5.xlarge"
    "r5.2xlarge"  = "r5.2xlarge"
  }
}

#------------------------------------------------------------------------------
# EKS Add-ons
#------------------------------------------------------------------------------

resource "aws_eks_addon" "main" {
  for_each = {
    for addon, enabled in {
      "vpc-cni"                 = var.kubernetes_config.addons.vpc_cni
      "coredns"                 = var.kubernetes_config.addons.coredns
      "kube-proxy"              = var.kubernetes_config.addons.kube_proxy
      "aws-ebs-csi-driver"      = var.kubernetes_config.addons.ebs_csi_driver
      "aws-efs-csi-driver"      = var.kubernetes_config.addons.efs_csi_driver
      "secrets-store-csi-driver" = var.kubernetes_config.addons.secrets_store_csi
    } : addon => addon if enabled
  }

  cluster_name             = aws_eks_cluster.main.name
  addon_name               = each.key
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"

  # Use IRSA for add-ons that support it
  service_account_role_arn = contains(["aws-ebs-csi-driver", "aws-efs-csi-driver"], each.key) ? (
    aws_iam_role.addon_roles[each.key].arn
  ) : null

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-${each.key}"
  })

  depends_on = [aws_eks_node_group.main]
}

#------------------------------------------------------------------------------
# Add-on IAM Roles
#------------------------------------------------------------------------------

resource "aws_iam_role" "addon_roles" {
  for_each = toset(compact([
    var.kubernetes_config.addons.ebs_csi_driver ? "aws-ebs-csi-driver" : "",
    var.kubernetes_config.addons.efs_csi_driver ? "aws-efs-csi-driver" : ""
  ]))

  name = "${var.kubernetes_config.cluster_name}-${each.key}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks[0].arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:${
            each.key == "aws-ebs-csi-driver" ? "ebs-csi-controller-sa" : "efs-csi-controller-sa"
          }"
        }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ebs_csi_policy" {
  count = var.kubernetes_config.addons.ebs_csi_driver ? 1 : 0

  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.addon_roles["aws-ebs-csi-driver"].name
}

resource "aws_iam_role_policy_attachment" "efs_csi_policy" {
  count = var.kubernetes_config.addons.efs_csi_driver ? 1 : 0

  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
  role       = aws_iam_role.addon_roles["aws-efs-csi-driver"].name
}

# Custom KMS policy for EBS CSI driver
resource "aws_iam_role_policy" "ebs_csi_kms" {
  count = var.kubernetes_config.addons.ebs_csi_driver ? 1 : 0

  name = "${var.kubernetes_config.cluster_name}-ebs-csi-kms"
  role = aws_iam_role.addon_roles["aws-ebs-csi-driver"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      Resource = aws_kms_key.main[var.kms_config.default_key_alias].arn
    }]
  })
}
