terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  name          = "Kubernetes"
  keyname       = "first-key-pair"
  instancetype  = "t3a.medium"
  ami           = "ami-0557a15b87f6559cf"
}

resource "aws_vpc" "my-vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "my-subnet-1" {
  vpc_id     = aws_vpc.my-vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "my-subnet-2" {
  vpc_id     = aws_vpc.my-vpc.id
  cidr_block = "10.0.2.0/24"
}

data "template_file" "worker" {
  template = file("${path.module}/worker.sh")
  vars = {
    region        = data.aws_region.current.name
    master_id     = aws_instance.master.id
    master_private_ip = aws_instance.master.private_ip
  }
}

data "template_file" "master" {
  template = file("${path.module}/master.sh")
}

resource "aws_instance" "master" {
  ami                  = local.ami
  instance_type        = local.instancetype
  key_name             = local.keyname
  iam_instance_profile = aws_iam_instance_profile.ec2connectprofile.name
  user_data            = data.template_file.master.rendered
  vpc_security_group_ids = [aws_security_group.tf-k8s-master-sec-gr.id]
  subnet_id            = aws_subnet.my-subnet-1.id
  tags = {
    Name = "${local.name}-kube-master"
  }
}

resource "aws_instance" "worker" {
  ami                  = local.ami
  instance_type        = local.instancetype
  key_name             = local.keyname
  iam_instance_profile = aws_iam_instance_profile.ec2connectprofile.name
  vpc_security_group_ids = [aws_security_group.tf-k8s-master-sec-gr.id]
  subnet_id            = aws_subnet.my-subnet-2.id
  user_data            = data.template_file.worker.rendered
  tags = {
    Name = "${local.name}-kube-worker"
  }
  depends_on = [aws_instance.master]
}

resource "aws_iam_instance_profile" "ec2connectprofile" {
  name = "ec2connectprofile-${local.name}"
  role = aws_iam_role.ec2connectcli.name
}

resource "aws_iam_role" "ec2connectcli" {
  name = "ec2connectcli-${local.name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect" : "Allow",
          "Action" : "ec2-instance-connect:SendSSHPublicKey",
          "Resource" : "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*",
          "Condition" : {
            "StringEquals" : {
              "ec2:osuser" : "ubuntu"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : "ec2:DescribeInstances",
          "Resource" : "*"
        }
      ]
    })
  }
}

resource "aws_security_group" "tf-k8s-master-sec-gr" {
  name = "${local.name}-k8s-master-sec-gr"
  tags = {
    Name = "${local.name}-k8s-master-sec-gr"
  }

  ingress {
    from_port = 0
    protocol  = "-1"
    to_port   = 0
    self = true
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EBS Volume
resource "aws_ebs_volume" "konzek_volume" {
  availability_zone = "us-east-1a"
  size              = 20
  tags = {
    Name = "konzek_volume"
  }
}

# S3 Bucket
resource "aws_s3_bucket" "konzek_bucket" {
  bucket = "konzek_bucket"
  acl    = "private"

  tags = {
    Name = "konzek_bucket"
  }
}

# EBS Volume Attachment
resource "aws_instance_volume_attachment" "konzek-volume-attachment" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.konzek_volume.id
  instance_id = aws_instance.master.id
}

# S3 Bucket ACL Configuration
resource "aws_s3_bucket_acl" "konzek-bucket-acl" {
  bucket = aws_s3_bucket.konzek_bucket.bucket
  acl    = "private"
}

output "master_public_dns" {
  value = aws_instance.master.public_dns
}

output "master_private_dns" {
  value = aws_instance.master.private_dns
}

output "worker_public_dns" {
  value = aws_instance.worker.public_dns
}

output "worker_private_dns" {
  value = aws_instance.worker.private_dns
}
