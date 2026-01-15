#------------------------------------------------------------------------------
# AWS GovCloud Environment Module - Security Resources
#
# Security groups, NACLs, and network security configurations
# for FedRAMP High / IL4-IL5 compliance.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Network ACLs - Defense in Depth
#------------------------------------------------------------------------------

# Public subnet NACL
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = var.network_config.subnet_tiers.public.enabled ? aws_subnet.public[*].id : []

  # Allow inbound HTTPS
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow inbound ephemeral ports (return traffic)
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow outbound to VPC CIDR
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound HTTPS
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow outbound ephemeral ports
  egress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-public-nacl"
    Tier = "public"
  })
}

# Private subnet NACL
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = var.network_config.subnet_tiers.private.enabled ? aws_subnet.private[*].id : []

  # Allow inbound from VPC CIDR
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Allow inbound ephemeral ports (return traffic from NAT)
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow outbound to VPC CIDR
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound HTTPS (for AWS API calls via NAT)
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow outbound ephemeral ports
  egress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-private-nacl"
    Tier = "private"
  })
}

# Isolated subnet NACL (most restrictive)
resource "aws_network_acl" "isolated" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = var.network_config.subnet_tiers.isolated.enabled ? aws_subnet.isolated[*].id : []

  # Only allow traffic from within VPC
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Only allow traffic to within VPC
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-isolated-nacl"
    Tier = "isolated"
  })
}

# Data subnet NACL (restricted to specific ports)
resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = var.network_config.subnet_tiers.data.enabled ? aws_subnet.data[*].id : []

  # Allow PostgreSQL from private subnets
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 5432
    to_port    = 5432
  }

  # Allow Redis from private subnets
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 6379
    to_port    = 6379
  }

  # Allow ephemeral ports (return traffic)
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 1024
    to_port    = 65535
  }

  # Allow outbound to VPC only
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.network_config.cidr_block
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-data-nacl"
    Tier = "data"
  })
}

#------------------------------------------------------------------------------
# Security Groups
#------------------------------------------------------------------------------

# Bastion / jump host security group
resource "aws_security_group" "bastion" {
  name        = "${var.environment_name}-bastion-sg"
  description = "Security group for bastion hosts"
  vpc_id      = aws_vpc.main.id

  # No ingress rules by default - use SSM Session Manager instead

  egress {
    description = "Allow HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.network_config.cidr_block]
  }

  egress {
    description = "Allow SSH to private subnets"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.network_config.cidr_block]
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-bastion-sg"
  })
}

# EKS cluster security group
resource "aws_security_group" "cluster" {
  name        = "${var.environment_name}-cluster-sg"
  description = "Security group for EKS cluster control plane"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-cluster-sg"
  })
}

# EKS node security group
resource "aws_security_group" "node" {
  name        = "${var.environment_name}-node-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name                                           = "${var.environment_name}-node-sg"
    "kubernetes.io/cluster/${var.kubernetes_config.cluster_name}" = "owned"
  })
}

# Data tier security group (databases)
resource "aws_security_group" "data" {
  name        = "${var.environment_name}-data-sg"
  description = "Security group for data tier (databases, caches)"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-data-sg"
  })
}

# VPC endpoints security group
resource "aws_security_group" "endpoints" {
  name        = "${var.environment_name}-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.network_config.cidr_block]
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment_name}-endpoints-sg"
  })
}

#------------------------------------------------------------------------------
# Security Group Rules - Cluster <-> Node Communication
#------------------------------------------------------------------------------

# Cluster to node communication
resource "aws_security_group_rule" "cluster_to_node" {
  type                     = "egress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow cluster to communicate with worker nodes"
}

resource "aws_security_group_rule" "cluster_to_node_https" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow cluster to communicate with worker nodes via HTTPS"
}

# Node to cluster communication
resource "aws_security_group_rule" "node_to_cluster" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow worker nodes to communicate with cluster API"
}

# Node to node communication
resource "aws_security_group_rule" "node_to_node" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow worker nodes to communicate with each other"
}

# Cluster to node (ingress)
resource "aws_security_group_rule" "cluster_to_node_ingress" {
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow cluster control plane to communicate with nodes"
}

resource "aws_security_group_rule" "cluster_to_node_ingress_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow cluster control plane to communicate with nodes via HTTPS"
}

# Node egress to VPC endpoints
resource "aws_security_group_rule" "node_to_endpoints" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.endpoints.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow nodes to communicate with VPC endpoints"
}

# Node egress to data tier
resource "aws_security_group_rule" "node_to_data_postgres" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.data.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow nodes to communicate with PostgreSQL"
}

resource "aws_security_group_rule" "node_to_data_redis" {
  type                     = "egress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.data.id
  security_group_id        = aws_security_group.node.id
  description              = "Allow nodes to communicate with Redis"
}

#------------------------------------------------------------------------------
# Security Group Rules - Data Tier
#------------------------------------------------------------------------------

# PostgreSQL from nodes
resource "aws_security_group_rule" "data_postgres_from_nodes" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.data.id
  description              = "Allow PostgreSQL connections from EKS nodes"
}

# Redis from nodes
resource "aws_security_group_rule" "data_redis_from_nodes" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.data.id
  description              = "Allow Redis connections from EKS nodes"
}
