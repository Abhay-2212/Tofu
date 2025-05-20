terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

#VPC
resource "aws_vpc" "Dalma-VPC" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Dalma-VPC"
  }
}

# Private Subnet 1
resource "aws_subnet" "Dalma-vpc-private-1" {
  vpc_id                  = aws_vpc.Dalma-VPC.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "Dalma-vpc-private-1"
  }
}

# Private Subnet 2
resource "aws_subnet" "Dalma-vpc-private-2" {
  vpc_id                  = aws_vpc.Dalma-VPC.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name = "Dalma-vpc-private-2"
  }
}

# Public Subnet 1
resource "aws_subnet" "Dalma-vpc-public-1" {
  vpc_id                  = aws_vpc.Dalma-VPC.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Dalma-vpc-public-1"
  }
}

# Public Subnet 2
resource "aws_subnet" "Dalma-vpc-public-2" {
  vpc_id                  = aws_vpc.Dalma-VPC.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "Dalma-vpc-public-2"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "dalma_igw" {
  vpc_id = aws_vpc.Dalma-VPC.id

  tags = {
    Name = "Dalma-IGW"
  }
}

# Route Table
resource "aws_route_table" "dalma_public_rt" {
  vpc_id = aws_vpc.Dalma-VPC.id

  tags = {
    Name = "Dalma-Public-RT"
  }
}

# Add IGW to Public RT
resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.dalma_public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.dalma_igw.id
}

# Associate Public Subnet 1 with Public Route Table
resource "aws_route_table_association" "public1_assoc" {
  subnet_id      = aws_subnet.Dalma-vpc-public-1.id
  route_table_id = aws_route_table.dalma_public_rt.id
}

# Associate Public Subnet 2 with Public Route Table
resource "aws_route_table_association" "public2_assoc" {
  subnet_id      = aws_subnet.Dalma-vpc-public-2.id
  route_table_id = aws_route_table.dalma_public_rt.id
}

# ALB Security Group
resource "aws_security_group" "dalma_alb_sg" {
  name        = "Dalma-ALB-SG"
  description = "Allow HTTP and HTTPS from anywhere"
  vpc_id      = aws_vpc.Dalma-VPC.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Jump Host Security Group
resource "aws_security_group" "jump_server_sg" {
  name        = "Jump-Server-SG"
  description = "Allow SSH from anywhere"
  vpc_id      = aws_vpc.Dalma-VPC.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Jump-Server-SG"
  }
}

# Dalma Server Security Group
resource "aws_security_group" "dalma_server_sg" {
  name        = "Dalma-server-SG"
  description = "Allow traffic from ALB and Jump Server"
  vpc_id      = aws_vpc.Dalma-VPC.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.dalma_alb_sg.id]
  }

  ingress {
    description     = "SSH from Jump Server"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.jump_server_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS Security Group
resource "aws_security_group" "dalma_rds_sg" {
  name        = "Dalma-RDS-SG"
  description = "Allow MySQL access from Dalma server and jump server"
  vpc_id      = aws_vpc.Dalma-VPC.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [
      aws_security_group.dalma_server_sg.id,
      aws_security_group.jump_server_sg.id
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Dalma-RDS-SG"
  }
}

# Dalma Server Key Pair
resource "tls_private_key" "dalma_server_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "dalma_server" {
  key_name   = "dalma-server-key"
  public_key = tls_private_key.dalma_server_key.public_key_openssh
}

resource "local_file" "dalma_server_private_key" {
  content              = tls_private_key.dalma_server_key.private_key_pem
  filename             = "${path.module}/dalma-server.pem"
  file_permission      = "0400"
  directory_permission = "0700"
}

# Jump Host Key Pair
resource "tls_private_key" "dalma_jump_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "dalma_jump" {
  key_name   = "dalma-jump-key"
  public_key = tls_private_key.dalma_jump_key.public_key_openssh
}

resource "local_file" "dalma_jump_private_key" {
  content              = tls_private_key.dalma_jump_key.private_key_pem
  filename             = "${path.module}/dalma-jump.pem"
  file_permission      = "0400"
  directory_permission = "0700"
}

# Dalma Server
resource "aws_instance" "Dalma-Server" {
  ami                    = data.aws_ami.ubuntu_2204.id
  instance_type          = local.ec2_instance_type_dalma
  subnet_id              = aws_subnet.Dalma-vpc-private-1.id
  vpc_security_group_ids = [aws_security_group.dalma_server_sg.id]
  key_name               = aws_key_pair.dalma_server.key_name

  root_block_device {
    volume_size = 200
    volume_type = "gp3"
  }

  tags = {
    Name = "Dalma-Server"
  }
}

# Jump Host
resource "aws_instance" "Jump-Host" {
  ami                         = data.aws_ami.ubuntu_2404.id
  instance_type               = local.ec2_instance_type_jump
  subnet_id                   = aws_subnet.Dalma-vpc-public-1.id
  vpc_security_group_ids      = [aws_security_group.jump_server_sg.id]
  key_name                    = aws_key_pair.dalma_jump.key_name
  associate_public_ip_address = true

  tags = {
    Name = "Jump-Host"
  }
}

# Target Group
resource "aws_lb_target_group" "dalma_tg" {
  name        = "Dalma-TG"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.Dalma-VPC.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }

  tags = {
    Name = "Dalma-TG"
  }
}

resource "aws_lb_target_group_attachment" "dalma_attachment" {
  target_group_arn = aws_lb_target_group.dalma_tg.arn
  target_id        = aws_instance.Dalma-Server.id
  port             = 80
}

# Load Balancer
resource "aws_lb" "dalma_alb" {
  name               = "Dalma-ALB"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dalma_alb_sg.id]
  subnets = [
    aws_subnet.Dalma-vpc-public-1.id,
    aws_subnet.Dalma-vpc-public-2.id
  ]

  tags = {
    Name = "Dalma-ALB"
  }
}

# Listner 80
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.dalma_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dalma_tg.arn
  }
}

# Subnet group
resource "aws_db_subnet_group" "dalma_subnet_group" {
  name        = "dalma-rds-subnet-group"
  description = "Private subnet group for Dalma RDS"
  subnet_ids = [
    aws_subnet.Dalma-vpc-private-1.id,
    aws_subnet.Dalma-vpc-private-2.id
  ]

  tags = {
    Name = "Dalma-RDS-Subnet-Group"
  }
}

# RDS
resource "aws_db_instance" "dalma_mysql" {
  identifier                = "dalma-mysql"
  engine                    = "mysql"
  engine_version            = "8.0.40"
  instance_class            = local.rds_instance_type
  allocated_storage         = 100
  storage_type              = "gp3"
  multi_az                  = false
  publicly_accessible       = false
  skip_final_snapshot       = true
  deletion_protection       = true
  db_name                   = "dalma"
  username                  = "admin"
  password                  = var.rds_password
  port                      = 3306
  vpc_security_group_ids    = [aws_security_group.dalma_rds_sg.id]
  db_subnet_group_name      = aws_db_subnet_group.dalma_subnet_group.name
  storage_encrypted         = true
  monitoring_interval       = 0
  performance_insights_enabled = false

  tags = {
    Name = "Dalma-RDS"
  }
}

# CloudWatch Loag Group
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-dalma-logs"
  retention_in_days = 7
}

# WAF
resource "aws_wafv2_web_acl" "dalma_waf" {
  name  = "dalma-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "DalmaWAF"
    sampled_requests_enabled   = true
  }

  # Common attack protections
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # SQL injection protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "Dalma-WAF"
  }
}

resource "aws_wafv2_web_acl_association" "dalma_waf_assoc" {
  resource_arn = aws_lb.dalma_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.dalma_waf.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "dalma_logging" {
  log_destination_configs = ["${aws_cloudwatch_log_group.waf_logs.arn}:*"]
  resource_arn            = aws_wafv2_web_acl.dalma_waf.arn
}

resource "aws_cloudwatch_log_resource_policy" "dalma-waf-policy" {
  policy_document = data.aws_iam_policy_document.dalma_waf_policy.json
  policy_name     = "webacl-policy-dalma-waf-log"
}

data "aws_iam_policy_document" "dalma_waf_policy" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type        = "Service"
    }
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.waf_logs.arn}:*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [tostring(data.aws_caller_identity.current.account_id)]
    }
  }
}
