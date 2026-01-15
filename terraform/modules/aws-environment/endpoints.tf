#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - VPC Endpoints
#
# PrivateLink endpoints for AWS services to ensure all traffic stays
# within the AWS network. Required for IL5 compliance.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Interface Endpoints
#------------------------------------------------------------------------------

# STS Endpoint (required for IRSA)
resource "aws_vpc_endpoint" "sts" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-sts-endpoint"
  })
}

# EC2 Endpoint
resource "aws_vpc_endpoint" "ec2" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ec2"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ec2-endpoint"
  })
}

# EC2 Messages (for SSM)
resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ec2messages-endpoint"
  })
}

# SSM Endpoints (for Session Manager)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ssm-endpoint"
  })
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ssmmessages-endpoint"
  })
}

# Autoscaling Endpoint
resource "aws_vpc_endpoint" "autoscaling" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.autoscaling"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-autoscaling-endpoint"
  })
}

# EKS Endpoint
resource "aws_vpc_endpoint" "eks" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.eks"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-eks-endpoint"
  })
}

# ECR API Endpoint
resource "aws_vpc_endpoint" "ecr_api" {
  count = var.private_endpoints.services.container_registry ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ecr-api-endpoint"
  })
}

# ECR DKR Endpoint (for docker pull)
resource "aws_vpc_endpoint" "ecr_dkr" {
  count = var.private_endpoints.services.container_registry ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-ecr-dkr-endpoint"
  })
}

# Secrets Manager Endpoint
resource "aws_vpc_endpoint" "secretsmanager" {
  count = var.private_endpoints.services.secrets_manager ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-secretsmanager-endpoint"
  })
}

# KMS Endpoint
resource "aws_vpc_endpoint" "kms" {
  count = var.private_endpoints.services.key_management ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-kms-endpoint"
  })
}

# CloudWatch Logs Endpoint
resource "aws_vpc_endpoint" "logs" {
  count = var.private_endpoints.services.logging ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-logs-endpoint"
  })
}

# CloudWatch Monitoring Endpoint
resource "aws_vpc_endpoint" "monitoring" {
  count = var.private_endpoints.services.monitoring ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.monitoring"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-monitoring-endpoint"
  })
}

# CloudWatch Events Endpoint
resource "aws_vpc_endpoint" "events" {
  count = var.private_endpoints.services.monitoring ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.events"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-events-endpoint"
  })
}

# ELB Endpoint
resource "aws_vpc_endpoint" "elasticloadbalancing" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.aws_region}.elasticloadbalancing"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = var.private_endpoints.private_dns_enabled

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-elb-endpoint"
  })
}

#------------------------------------------------------------------------------
# Gateway Endpoints
#------------------------------------------------------------------------------

# S3 Gateway Endpoint
resource "aws_vpc_endpoint" "s3" {
  count = var.private_endpoints.services.storage ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${local.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = compact(concat(
    var.network_config.subnet_tiers.public.enabled ? [aws_route_table.public[0].id] : [],
    var.network_config.subnet_tiers.private.enabled ? aws_route_table.private[*].id : [],
    var.network_config.subnet_tiers.isolated.enabled ? [aws_route_table.isolated[0].id] : [],
    var.network_config.subnet_tiers.data.enabled ? [aws_route_table.data[0].id] : []
  ))

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-s3-endpoint"
  })
}

# DynamoDB Gateway Endpoint
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${local.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"

  route_table_ids = compact(concat(
    var.network_config.subnet_tiers.public.enabled ? [aws_route_table.public[0].id] : [],
    var.network_config.subnet_tiers.private.enabled ? aws_route_table.private[*].id : [],
    var.network_config.subnet_tiers.isolated.enabled ? [aws_route_table.isolated[0].id] : [],
    var.network_config.subnet_tiers.data.enabled ? [aws_route_table.data[0].id] : []
  ))

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-dynamodb-endpoint"
  })
}
