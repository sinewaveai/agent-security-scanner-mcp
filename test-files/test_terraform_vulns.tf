# Test file for Terraform security rules
# Contains intentional vulnerabilities for testing

# S3 Public Access - should be detected
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket" "public_rw_bucket" {
  bucket = "my-public-rw-bucket"
  acl    = "public-read-write"
}

# Security Group Open to World - should be detected
resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Admin Policy - should be detected
resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        "Action" : "*"
        "Resource" : "*"
      }
    ]
  })
}

# IAM User Policy Attachment - should be detected
resource "aws_iam_user_policy_attachment" "user_admin" {
  user       = aws_iam_user.admin.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

resource "aws_iam_user_policy" "direct_policy" {
  name = "direct-policy"
  user = aws_iam_user.admin.name
}

# RDS Public Access - should be detected
resource "aws_db_instance" "public_db" {
  identifier          = "public-database"
  engine              = "mysql"
  publicly_accessible = true
  storage_encrypted   = false
  deletion_protection = false
}

# CloudTrail Disabled - should be detected
resource "aws_cloudtrail" "disabled_trail" {
  name           = "disabled-trail"
  s3_bucket_name = aws_s3_bucket.trail_bucket.id
  enable_logging = false
  is_multi_region_trail = false
}

# KMS Key Rotation Disabled - should be detected
resource "aws_kms_key" "no_rotation" {
  description         = "No rotation key"
  enable_key_rotation = false
}

# EBS Not Encrypted - should be detected
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 100
  encrypted         = false
}

# EC2 IMDSv1 - should be detected
resource "aws_instance" "imdsv1" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

# Hardcoded Credentials - should be detected
resource "aws_db_instance" "hardcoded_creds" {
  identifier = "hardcoded-db"
  engine     = "mysql"
  password   = "SuperSecretPassword123!"
  master_password = "AnotherSecret456!"
}

variable "api_key" {
  default = "sk_test_EXAMPLE_DO_NOT_USE_fake123"
}

# AWS Access Key Hardcoded - should be detected
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
