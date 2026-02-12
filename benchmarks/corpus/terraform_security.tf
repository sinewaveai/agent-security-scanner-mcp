# Benchmark corpus: Terraform AWS security vulnerabilities

# --- S3 Bucket Security ---

# VULN: s3-public-read
resource "aws_s3_bucket" "insecure_public" {
  bucket = "my-bucket"
  acl    = "public-read"
}

# VULN: s3-encryption-disabled
resource "aws_s3_bucket" "no_encryption" {
  bucket = "my-bucket"
}

# VULN: s3-versioning-disabled
resource "aws_s3_bucket" "no_versioning" {
  bucket = "my-bucket"
  versioning {
    enabled = false
  }
}

# VULN: s3-logging-disabled
resource "aws_s3_bucket" "no_logging" {
  bucket = "my-bucket"
}

# SAFE: s3-public-read
resource "aws_s3_bucket" "secure_private" {
  bucket = "my-secure-bucket"
  acl    = "private"
}

# SAFE: s3-encryption-disabled
resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# --- Security Groups ---

# VULN: security-group-open-ingress
resource "aws_security_group" "open_all" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULN: security-group-open-ssh
resource "aws_security_group" "open_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULN: security-group-open-rdp
resource "aws_security_group" "open_rdp" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SAFE: security-group-open-ssh
resource "aws_security_group" "restricted_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# --- IAM ---

# VULN: iam-admin-policy
resource "aws_iam_policy" "admin_policy" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# VULN: iam-user-policy-attachment
resource "aws_iam_user_policy_attachment" "direct_attach" {
  user       = aws_iam_user.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SAFE: iam-admin-policy
resource "aws_iam_policy" "restricted_policy" {
  policy = jsonencode({
    Statement = [{
      Action   = ["s3:GetObject"]
      Effect   = "Allow"
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}

# --- RDS ---

# VULN: rds-public-access
resource "aws_db_instance" "public_rds" {
  publicly_accessible = true
}

# VULN: rds-encryption-disabled
resource "aws_db_instance" "unencrypted_rds" {
  storage_encrypted = false
}

# VULN: rds-deletion-protection
resource "aws_db_instance" "no_protection" {
  deletion_protection = false
}

# SAFE: rds-public-access
resource "aws_db_instance" "private_rds" {
  publicly_accessible = false
  storage_encrypted   = true
  deletion_protection = true
}

# --- CloudTrail ---

# VULN: cloudtrail-disabled
resource "aws_cloudtrail" "disabled_trail" {
  enable_logging = false
}

# VULN: cloudtrail-encryption
resource "aws_cloudtrail" "unencrypted_trail" {
  name = "my-trail"
}

# SAFE: cloudtrail-disabled
resource "aws_cloudtrail" "enabled_trail" {
  name            = "my-trail"
  enable_logging  = true
  kms_key_id      = aws_kms_key.cloudtrail.arn
}

# --- KMS ---

# VULN: kms-key-rotation
resource "aws_kms_key" "no_rotation" {
  enable_key_rotation = false
}

# SAFE: kms-key-rotation
resource "aws_kms_key" "with_rotation" {
  enable_key_rotation = true
}

# --- EBS ---

# VULN: ebs-encryption-disabled
resource "aws_ebs_volume" "unencrypted" {
  encrypted = false
}

# SAFE: ebs-encryption-disabled
resource "aws_ebs_volume" "encrypted" {
  encrypted = true
}

# --- EC2 ---

# VULN: ec2-imdsv1
resource "aws_instance" "imdsv1" {
  metadata_options {
    http_tokens = "optional"
  }
}

# SAFE: ec2-imdsv1
resource "aws_instance" "imdsv2" {
  metadata_options {
    http_tokens = "required"
  }
}

# --- Hardcoded Secrets ---

# VULN: hardcoded-password
variable "db_password" {
  default = "SuperSecret123!"
}

# VULN: hardcoded-api-key
locals {
  api_key = "test_FAKEFAKEFAKE1234"
}

# SAFE: hardcoded-password
variable "db_password_secure" {
  description = "Database password"
  sensitive   = true
}
