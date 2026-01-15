#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - Main Configuration
#
# This module implements the Environment Contract Interface for AWS GovCloud.
# Designed for FedRAMP High / IL4-IL5 classification levels.
#
# Resources created:
# - VPC with tiered subnets (public, private, isolated, data)
# - EKS cluster with managed node groups
# - KMS customer-managed keys with HSM backing
# - IAM roles and policies
# - VPC endpoints for AWS services
# - CloudWatch logging and monitoring
# - Security Hub, GuardDuty, Config
# - Backup vault and plans
#------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

#------------------------------------------------------------------------------
# Data Sources
#------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# Map cloud-agnostic region to AWS GovCloud region
locals {
  aws_region_map = {
    "gov-west-1" = "us-gov-west-1"
    "gov-east-1" = "us-gov-east-1"
  }

  aws_region   = lookup(local.aws_region_map, var.region, var.region)
  account_id   = data.aws_caller_identity.current.account_id
  partition    = data.aws_partition.current.partition
  dns_suffix   = data.aws_partition.current.dns_suffix

  # Merge required and additional tags
  common_tags = merge(
    {
      Owner           = var.required_tags.Owner
      Environment     = var.required_tags.Environment
      Classification  = var.required_tags.Classification
      CostCenter      = var.required_tags.CostCenter
      DataSensitivity = var.required_tags.DataSensitivity
      Compliance      = var.required_tags.Compliance
      ManagedBy       = "terraform"
      Module          = "aws-environment"
    },
    var.additional_tags
  )
}

# Availability zones for the region
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.network_config.availability_zone_count)
}

#------------------------------------------------------------------------------
# VPC and Core Networking
#------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.network_config.cidr_block
  enable_dns_hostnames = var.network_config.dns_config.enable_dns_hostnames
  enable_dns_support   = var.network_config.dns_config.enable_dns_support

  # IL5 requirement: Instance tenancy
  instance_tenancy = var.classification_level == "IL5" ? "dedicated" : "default"

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-vpc"
  })
}

#------------------------------------------------------------------------------
# Public Subnets (if enabled)
#------------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = var.network_config.subnet_tiers.public.enabled ? var.network_config.availability_zone_count : 0

  vpc_id                  = aws_vpc.main.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.network_config.cidr_block, var.network_config.subnet_tiers.public.cidr_bits, count.index)
  map_public_ip_on_launch = false  # IL5: Never auto-assign public IPs

  tags = merge(local.common_tags, {
    Name                                           = "${var.environment_name}-public-${local.azs[count.index]}"
    Tier                                           = "public"
    "kubernetes.io/role/elb"                       = "1"
    "kubernetes.io/cluster/${var.kubernetes_config.cluster_name}" = "shared"
  })
}

#------------------------------------------------------------------------------
# Private Subnets (application workloads)
#------------------------------------------------------------------------------

resource "aws_subnet" "private" {
  count = var.network_config.subnet_tiers.private.enabled ? var.network_config.availability_zone_count : 0

  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block = cidrsubnet(
    var.network_config.cidr_block,
    var.network_config.subnet_tiers.private.cidr_bits,
    count.index + var.network_config.availability_zone_count
  )

  tags = merge(local.common_tags, {
    Name                                           = "${var.environment_name}-private-${local.azs[count.index]}"
    Tier                                           = "private"
    "kubernetes.io/role/internal-elb"              = "1"
    "kubernetes.io/cluster/${var.kubernetes_config.cluster_name}" = "shared"
  })
}

#------------------------------------------------------------------------------
# Isolated Subnets (no internet access)
#------------------------------------------------------------------------------

resource "aws_subnet" "isolated" {
  count = var.network_config.subnet_tiers.isolated.enabled ? var.network_config.availability_zone_count : 0

  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block = cidrsubnet(
    var.network_config.cidr_block,
    var.network_config.subnet_tiers.isolated.cidr_bits,
    count.index + (var.network_config.availability_zone_count * 2)
  )

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-isolated-${local.azs[count.index]}"
    Tier = "isolated"
  })
}

#------------------------------------------------------------------------------
# Data Subnets (databases, sensitive workloads)
#------------------------------------------------------------------------------

resource "aws_subnet" "data" {
  count = var.network_config.subnet_tiers.data.enabled ? var.network_config.availability_zone_count : 0

  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block = cidrsubnet(
    var.network_config.cidr_block,
    var.network_config.subnet_tiers.data.cidr_bits,
    count.index + (var.network_config.availability_zone_count * 3)
  )

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-data-${local.azs[count.index]}"
    Tier = "data"
  })
}

#------------------------------------------------------------------------------
# Internet Gateway (for public subnets if enabled)
#------------------------------------------------------------------------------

resource "aws_internet_gateway" "main" {
  count = var.network_config.subnet_tiers.public.enabled ? 1 : 0

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-igw"
  })
}

#------------------------------------------------------------------------------
# NAT Gateways (one per AZ for high availability)
#------------------------------------------------------------------------------

resource "aws_eip" "nat" {
  count = var.network_config.subnet_tiers.public.nat_gateway ? var.network_config.availability_zone_count : 0

  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-nat-eip-${local.azs[count.index]}"
  })

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = var.network_config.subnet_tiers.public.nat_gateway ? var.network_config.availability_zone_count : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-nat-${local.azs[count.index]}"
  })

  depends_on = [aws_internet_gateway.main]
}

#------------------------------------------------------------------------------
# Route Tables
#------------------------------------------------------------------------------

# Public route table
resource "aws_route_table" "public" {
  count = var.network_config.subnet_tiers.public.enabled ? 1 : 0

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-public-rt"
    Tier = "public"
  })
}

resource "aws_route" "public_internet" {
  count = var.network_config.subnet_tiers.public.enabled ? 1 : 0

  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main[0].id
}

resource "aws_route_table_association" "public" {
  count = var.network_config.subnet_tiers.public.enabled ? var.network_config.availability_zone_count : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# Private route tables (one per AZ for NAT gateway)
resource "aws_route_table" "private" {
  count = var.network_config.subnet_tiers.private.enabled ? var.network_config.availability_zone_count : 0

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-private-rt-${local.azs[count.index]}"
    Tier = "private"
  })
}

resource "aws_route" "private_nat" {
  count = var.network_config.subnet_tiers.public.nat_gateway ? var.network_config.availability_zone_count : 0

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "private" {
  count = var.network_config.subnet_tiers.private.enabled ? var.network_config.availability_zone_count : 0

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Isolated route tables (no external routes)
resource "aws_route_table" "isolated" {
  count = var.network_config.subnet_tiers.isolated.enabled ? 1 : 0

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-isolated-rt"
    Tier = "isolated"
  })
}

resource "aws_route_table_association" "isolated" {
  count = var.network_config.subnet_tiers.isolated.enabled ? var.network_config.availability_zone_count : 0

  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated[0].id
}

# Data route tables (no external routes)
resource "aws_route_table" "data" {
  count = var.network_config.subnet_tiers.data.enabled ? 1 : 0

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-data-rt"
    Tier = "data"
  })
}

resource "aws_route_table_association" "data" {
  count = var.network_config.subnet_tiers.data.enabled ? var.network_config.availability_zone_count : 0

  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data[0].id
}

#------------------------------------------------------------------------------
# VPC Flow Logs (Required for IL4+)
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.environment_name}/flow-logs"
  retention_in_days = var.network_config.flow_logs.retention_days
  kms_key_id        = aws_kms_key.main[var.kms_config.default_key_alias].arn

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-flow-logs"
  })
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.environment_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.environment_name}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = var.network_config.flow_logs.traffic_type
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60  # 1 minute for IL5 compliance

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-flow-log"
  })
}

#------------------------------------------------------------------------------
# Private DNS Zone
#------------------------------------------------------------------------------

resource "aws_route53_zone" "private" {
  name = var.network_config.dns_config.private_zone_name

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-private-zone"
  })
}
