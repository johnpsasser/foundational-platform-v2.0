#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - IAM Configuration
#
# IAM roles, policies, and service accounts for FedRAMP High / IL4-IL5.
# Implements least-privilege access and IRSA for Kubernetes workloads.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# EKS Cluster IAM Role
#------------------------------------------------------------------------------

resource "aws_iam_role" "cluster" {
  name = "${var.kubernetes_config.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-cluster-role"
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster_vpc_controller" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

# Custom policy for KMS encryption
resource "aws_iam_role_policy" "cluster_kms" {
  name = "${var.kubernetes_config.cluster_name}-cluster-kms"
  role = aws_iam_role.cluster.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
        "kms:CreateGrant"
      ]
      Resource = aws_kms_key.main[var.kms_config.default_key_alias].arn
    }]
  })
}

#------------------------------------------------------------------------------
# EKS Node IAM Role
#------------------------------------------------------------------------------

resource "aws_iam_role" "node" {
  name = "${var.kubernetes_config.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.kubernetes_config.cluster_name}-node-role"
  })
}

resource "aws_iam_role_policy_attachment" "node_policy" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_container_registry" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_ssm" {
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.node.name
}

# Custom policy for node KMS access
resource "aws_iam_role_policy" "node_kms" {
  name = "${var.kubernetes_config.cluster_name}-node-kms"
  role = aws_iam_role.node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
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

resource "aws_iam_instance_profile" "node" {
  name = "${var.kubernetes_config.cluster_name}-node-profile"
  role = aws_iam_role.node.name

  tags = local.common_tags
}

#------------------------------------------------------------------------------
# Service Account IAM Roles (IRSA)
#------------------------------------------------------------------------------

resource "aws_iam_role" "service_account" {
  for_each = var.iam_config.service_accounts

  name = "${var.kubernetes_config.cluster_name}-${each.key}-sa-role"

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
          "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:${each.value.namespace}:${each.value.name}"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name              = "${var.kubernetes_config.cluster_name}-${each.key}-sa-role"
    ServiceAccount    = each.value.name
    Namespace         = each.value.namespace
  })
}

# Generate IAM policies from cloud-agnostic permission definitions
# Note: For simplicity, this uses pre-defined ARN patterns. In production,
# you would use a more sophisticated ARN builder or separate policy resources.
resource "aws_iam_role_policy" "service_account" {
  for_each = var.iam_config.service_accounts

  name = "${var.kubernetes_config.cluster_name}-${each.key}-sa-policy"
  role = aws_iam_role.service_account[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for perm in each.value.permissions : {
        Effect   = "Allow"
        Action   = local.permission_action_map[perm.service][perm.actions[0]]
        Resource = perm.resources
      }
    ]
  })
}

#------------------------------------------------------------------------------
# Permission Mapping (cloud-agnostic to AWS IAM)
#------------------------------------------------------------------------------

locals {
  # Map cloud-agnostic service permissions to AWS IAM actions
  permission_action_map = {
    "storage" = {
      "read"   = ["s3:GetObject", "s3:ListBucket"]
      "write"  = ["s3:PutObject", "s3:DeleteObject"]
      "full"   = ["s3:*"]
    }
    "secrets" = {
      "read"   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      "write"  = ["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret"]
      "full"   = ["secretsmanager:*"]
    }
    "database" = {
      "read"   = ["rds:Describe*", "rds-db:connect"]
      "write"  = ["rds:Modify*"]
      "full"   = ["rds:*", "rds-db:*"]
    }
    "kms" = {
      "encrypt" = ["kms:Encrypt", "kms:GenerateDataKey*"]
      "decrypt" = ["kms:Decrypt"]
      "full"    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    }
    "sqs" = {
      "read"   = ["sqs:ReceiveMessage", "sqs:GetQueueAttributes"]
      "write"  = ["sqs:SendMessage"]
      "full"   = ["sqs:*"]
    }
    "sns" = {
      "publish" = ["sns:Publish"]
      "full"    = ["sns:*"]
    }
  }

  # ARN pattern templates for documentation (resources should be passed as full ARNs)
  # In production, use a separate module or data source for ARN construction
  arn_patterns = {
    "storage"  = "arn:${local.partition}:s3:::BUCKET_NAME/*"
    "secrets"  = "arn:${local.partition}:secretsmanager:${local.aws_region}:${local.account_id}:secret:SECRET_NAME"
    "database" = "arn:${local.partition}:rds:${local.aws_region}:${local.account_id}:db:DB_NAME"
    "kms"      = "arn:${local.partition}:kms:${local.aws_region}:${local.account_id}:key/KEY_ID"
    "sqs"      = "arn:${local.partition}:sqs:${local.aws_region}:${local.account_id}:QUEUE_NAME"
    "sns"      = "arn:${local.partition}:sns:${local.aws_region}:${local.account_id}:TOPIC_NAME"
  }
}

#------------------------------------------------------------------------------
# Cross-Account Trust (if configured)
#------------------------------------------------------------------------------

resource "aws_iam_role" "cross_account" {
  count = length(var.iam_config.trusted_principals) > 0 ? 1 : 0

  name = "${var.environment_name}-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for principal in var.iam_config.trusted_principals : {
        Effect = "Allow"
        Principal = principal.type == "account" ? {
          AWS = "arn:${local.partition}:iam::${principal.identifier}:root"
        } : principal.type == "service" ? {
          Service = principal.identifier
        } : {
          Federated = principal.identifier
        }
        Action = "sts:AssumeRole"
        Condition = length(principal.conditions) > 0 ? {
          StringEquals = principal.conditions
        } : null
      }
    ]
  })

  # MFA requirement for human access
  max_session_duration = var.iam_config.max_session_duration

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-cross-account-role"
  })
}

#------------------------------------------------------------------------------
# IAM Password Policy (IL5 Requirements)
#------------------------------------------------------------------------------

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 60
  password_reuse_prevention      = 24
  hard_expiry                    = false
}
