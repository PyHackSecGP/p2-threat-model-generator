"""Tests for the Terraform (.tf) HCL parser.

Uses python-hcl2 when installed, otherwise the stdlib regex fallback —
both backends must pass these tests.
"""
from __future__ import annotations
from pathlib import Path

from models import ComponentType, Severity, StrideCategory
from parsers.terraform_parser import parse_terraform
from engine.stride import run_stride


# ── Fixtures ──────────────────────────────────────────────────────────────────

_PUBLIC_BUCKET = '''
resource "aws_s3_bucket" "public_assets" {
  bucket = "my-public-assets"
  acl    = "public-read"
}
'''

_IAM_WILDCARD = '''
resource "aws_iam_role" "admin" {
  name = "admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "*" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "wildcard" {
  name   = "full-access"
  policy = "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"
}
'''

_UNENCRYPTED_RDS = '''
resource "aws_db_instance" "legacy" {
  identifier         = "legacy-db"
  engine             = "postgres"
  storage_encrypted  = false
  instance_class     = "db.t3.medium"
  allocated_storage  = 20
}
'''

_OPEN_SG = '''
resource "aws_security_group" "web_open" {
  name = "web-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

_MULTI_RESOURCE = '''
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}

resource "aws_db_instance" "pg" {
  identifier        = "prod-pg"
  engine            = "postgres"
  storage_encrypted = true
}

resource "aws_s3_bucket" "private" {
  bucket = "private-data"
  acl    = "private"
}

resource "aws_iam_role" "app_role" {
  name               = "app-role"
  assume_role_policy = "{}"
}
'''


def _write(tmp_path: Path, content: str) -> str:
    f = tmp_path / "main.tf"
    f.write_text(content)
    return str(f)


# ── Parser extraction tests ───────────────────────────────────────────────────

def test_parses_resource_blocks_into_components(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _MULTI_RESOURCE))
    types = {c.technology for c in app.components}
    assert "aws_instance" in types
    assert "aws_db_instance" in types
    assert "aws_s3_bucket" in types
    assert "aws_iam_role" in types


def test_maps_resource_types_to_stride_component_types(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _MULTI_RESOURCE))
    kinds = {c.technology: c.type for c in app.components}
    assert kinds["aws_instance"] == ComponentType.WEB_APP
    assert kinds["aws_db_instance"] == ComponentType.DATABASE
    assert kinds["aws_s3_bucket"] == ComponentType.STORAGE
    assert kinds["aws_iam_role"] == ComponentType.AUTH_SERVICE


def test_provider_block_captured_in_description(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _MULTI_RESOURCE))
    assert "aws" in app.description.lower()


# ── Terraform-specific rule tests ─────────────────────────────────────────────

def test_public_s3_bucket_generates_info_disclosure_threat(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _PUBLIC_BUCKET))
    threats = run_stride(app)
    tf_threats = [t for t in threats if t.id.startswith("TF")]
    assert any(
        "Public S3" in t.title and t.stride_category == StrideCategory.INFO_DISCLOSURE
        for t in tf_threats
    ), f"Expected Public S3 threat; got {[t.title for t in tf_threats]}"


def test_iam_wildcard_generates_eop_threat(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _IAM_WILDCARD))
    threats = run_stride(app)
    tf_threats = [t for t in threats if t.id.startswith("TF")]
    assert any(
        "Wildcard IAM" in t.title and t.stride_category == StrideCategory.ELEVATION_OF_PRIVILEGE
        for t in tf_threats
    ), f"Expected Wildcard IAM threat; got {[t.title for t in tf_threats]}"


def test_unencrypted_rds_generates_info_disclosure_threat(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _UNENCRYPTED_RDS))
    threats = run_stride(app)
    tf_threats = [t for t in threats if t.id.startswith("TF")]
    assert any(
        "Unencrypted RDS" in t.title and t.stride_category == StrideCategory.INFO_DISCLOSURE
        for t in tf_threats
    )


def test_security_group_open_ingress_generates_tampering_threat(tmp_path: Path) -> None:
    app = parse_terraform(_write(tmp_path, _OPEN_SG))
    threats = run_stride(app)
    tf_threats = [t for t in threats if t.id.startswith("TF")]
    assert any(
        "Open Ingress" in t.title and t.stride_category == StrideCategory.TAMPERING
        for t in tf_threats
    )


def test_private_bucket_does_not_generate_public_threat(tmp_path: Path) -> None:
    """Regression — ensure the public-S3 rule does not false-positive on acl=private."""
    app = parse_terraform(_write(tmp_path, _MULTI_RESOURCE))
    threats = run_stride(app)
    assert not any("Public S3" in t.title for t in threats)


def test_terraform_threats_feed_into_overall_risk_score(tmp_path: Path) -> None:
    """A single public bucket + wildcard IAM should land as Critical or High severity."""
    tf = _PUBLIC_BUCKET + "\n" + _IAM_WILDCARD
    app = parse_terraform(_write(tmp_path, tf))
    threats = run_stride(app)
    tf_threats = [t for t in threats if t.id.startswith("TF")]
    assert any(t.severity in (Severity.CRITICAL, Severity.HIGH) for t in tf_threats)
