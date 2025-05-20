# Get current region
data "aws_region" "current" {}

# Get AWS account ID
data "aws_caller_identity" "current" {}

# Latest Ubuntu 22.04 LTS AMI for Dalma Server
data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Latest Ubuntu 24.04 LTS AMI for Jump Host
data "aws_ssm_parameter" "ubuntu_2404_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_ami" "ubuntu_2404" {
  most_recent = false
  owners      = ["099720109477"]

  filter {
    name   = "image-id"
    values = [data.aws_ssm_parameter.ubuntu_2404_ami.value]
  }
}


# Define instance types as locals
locals {
  ec2_instance_type_dalma = "t3.micro"
  ec2_instance_type_jump  = "t3.micro"
  rds_instance_type       = "db.t3.micro"
}
