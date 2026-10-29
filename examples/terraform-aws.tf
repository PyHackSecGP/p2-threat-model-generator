## Example Terraform configuration — demonstrates the parser on common AWS resources.
## Includes intentional misconfigurations the parser will flag:
##   - public S3 bucket (acl = "public-read")
##   - IAM role with wildcard Action and Principal
##   - RDS instance with storage_encrypted = false
##   - Security group with 0.0.0.0/0 ingress on port 22

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "example-public-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket" "private_data" {
  bucket = "example-private-data"
  acl    = "private"
}

resource "aws_iam_role" "admin" {
  name               = "example-admin"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sts:AssumeRole\"}]}"
}

resource "aws_iam_policy" "full_access" {
  name   = "example-full-access"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}

resource "aws_db_instance" "legacy" {
  identifier        = "example-legacy-db"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 20
  storage_encrypted = false
}

resource "aws_security_group" "web_open" {
  name = "example-web-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami           = "ami-123456"
  instance_type = "t3.micro"
}

resource "aws_lb" "web" {
  name               = "example-web-lb"
  load_balancer_type = "application"
}
