#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - Transit Gateway
#
# Multi-VPC connectivity using Transit Gateway for hub-and-spoke architecture.
# Enables secure communication between environments and on-premises networks.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Transit Gateway
#------------------------------------------------------------------------------

resource "aws_ec2_transit_gateway" "main" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  description                     = "Transit Gateway for ${var.environment_name}"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "disable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw"
  })
}

#------------------------------------------------------------------------------
# Transit Gateway VPC Attachment
#------------------------------------------------------------------------------

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  transit_gateway_id = aws_ec2_transit_gateway.main[0].id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : aws_subnet.isolated[*].id

  dns_support                                     = "enable"
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw-attachment"
  })
}

#------------------------------------------------------------------------------
# Transit Gateway Route Tables
#------------------------------------------------------------------------------

# Shared services route table
resource "aws_ec2_transit_gateway_route_table" "shared" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  transit_gateway_id = aws_ec2_transit_gateway.main[0].id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw-rt-shared"
  })
}

# Isolated route table (no cross-VPC communication)
resource "aws_ec2_transit_gateway_route_table" "isolated" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  transit_gateway_id = aws_ec2_transit_gateway.main[0].id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw-rt-isolated"
  })
}

# Route table for transit attachments
resource "aws_ec2_transit_gateway_route_table" "main" {
  for_each = var.transit_config.enable_transit_gateway ? {
    for att in var.transit_config.transit_attachments : att.name => att
  } : {}

  transit_gateway_id = aws_ec2_transit_gateway.main[0].id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw-rt-${each.key}"
  })
}

#------------------------------------------------------------------------------
# Transit Gateway Route Table Associations
#------------------------------------------------------------------------------

resource "aws_ec2_transit_gateway_route_table_association" "main" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.main[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.shared[0].id
}

#------------------------------------------------------------------------------
# Transit Gateway Route Table Propagations
#------------------------------------------------------------------------------

resource "aws_ec2_transit_gateway_route_table_propagation" "main" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.main[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.shared[0].id
}

#------------------------------------------------------------------------------
# VPC Routes to Transit Gateway
#------------------------------------------------------------------------------

# Add routes from private subnets to transit gateway for cross-VPC traffic
resource "aws_route" "private_to_tgw" {
  count = var.transit_config.enable_transit_gateway && var.network_config.subnet_tiers.private.enabled ? var.network_config.availability_zone_count : 0

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "10.0.0.0/8"  # Summary route for all internal networks
  transit_gateway_id     = aws_ec2_transit_gateway.main[0].id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

#------------------------------------------------------------------------------
# RAM Resource Share (for cross-account Transit Gateway sharing)
#------------------------------------------------------------------------------

resource "aws_ram_resource_share" "tgw" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  name                      = "${var.environment_name}-tgw-share"
  allow_external_principals = false

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-tgw-share"
  })
}

resource "aws_ram_resource_association" "tgw" {
  count = var.transit_config.enable_transit_gateway ? 1 : 0

  resource_arn       = aws_ec2_transit_gateway.main[0].arn
  resource_share_arn = aws_ram_resource_share.tgw[0].arn
}

#------------------------------------------------------------------------------
# VPN Gateway (backup connectivity)
#------------------------------------------------------------------------------

resource "aws_vpn_gateway" "main" {
  count = var.transit_config.vpn_backup.enabled ? 1 : 0

  vpc_id          = aws_vpc.main.id
  amazon_side_asn = 65000

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-vpn-gw"
  })
}

resource "aws_vpn_gateway_attachment" "main" {
  count = var.transit_config.vpn_backup.enabled ? 1 : 0

  vpc_id         = aws_vpc.main.id
  vpn_gateway_id = aws_vpn_gateway.main[0].id
}

# Enable VPN gateway route propagation
resource "aws_vpn_gateway_route_propagation" "private" {
  count = var.transit_config.vpn_backup.enabled && var.network_config.subnet_tiers.private.enabled ? var.network_config.availability_zone_count : 0

  vpn_gateway_id = aws_vpn_gateway.main[0].id
  route_table_id = aws_route_table.private[count.index].id
}
