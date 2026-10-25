# forge-iaas AWS example — S3 bucket, no other AWS resources.
#
# Run it with forge-iaas (see README.md in this directory):
#   1. Set AWS credentials as *env* variables on the workspace
#      (category "env", sensitive): AWS_ACCESS_KEY_ID,
#      AWS_SECRET_ACCESS_KEY, and optionally AWS_SESSION_TOKEN.
#   2. Set the region as a *terraform* variable (category
#      "terraform"): aws_region, e.g. "ap-southeast-1".
#      (Or set AWS_REGION as an env variable instead and drop the
#      provider's region argument — the provider reads it from env.)
#   3. Plan, approve, apply. The AWS provider is downloaded by
#      `tofu init` from the OpenTofu registry; forge-iaas itself
#      never talks to AWS — only the tofu subprocess does, with
#      exactly the env variables the workspace set.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region for the bucket"
  default     = "ap-southeast-1"
}

variable "bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name"
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name

  tags = {
    Name      = var.bucket_name
    ManagedBy = "forge-iaas"
  }
}

output "bucket_id" {
  value = aws_s3_bucket.example.id
}
