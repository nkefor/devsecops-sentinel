"""CIS Benchmark mappings for common security checks."""

# CIS Benchmark mappings for Checkov and Trivy checks
CIS_BENCHMARK_MAP = {
    # Security Group Issues
    "CKV_AWS_23": {
        "id": "CIS AWS 5.2",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "description": "Security groups should restrict SSH access to specific IP ranges",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_24": {
        "id": "CIS AWS 5.3",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        "description": "Security groups should restrict RDP access to specific IP ranges",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_25": {
        "id": "CIS AWS 5.4",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
        "description": "Security groups should not allow unrestricted access to administrative ports",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # S3 Bucket Issues
    "CKV_AWS_18": {
        "id": "CIS AWS 2.1.1",
        "title": "Ensure S3 bucket access logging is enabled",
        "description": "S3 access logging provides records for security and access audits",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_19": {
        "id": "CIS AWS 2.1.2",
        "title": "Ensure S3 bucket has server-side encryption enabled",
        "description": "S3 bucket data should be encrypted at rest",
        "level": 2,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_20": {
        "id": "CIS AWS 2.1.5",
        "title": "Ensure S3 bucket does not have a public ACL",
        "description": "S3 buckets should not be publicly accessible",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_21": {
        "id": "CIS AWS 2.1.3",
        "title": "Ensure S3 bucket versioning is enabled",
        "description": "Versioning provides data protection and recovery capabilities",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV2_AWS_6": {
        "id": "CIS AWS 2.1.5",
        "title": "Ensure S3 bucket has public access blocks",
        "description": "Public access blocks prevent accidental exposure of bucket data",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # RDS Issues
    "CKV_AWS_16": {
        "id": "CIS AWS 2.3.1",
        "title": "Ensure RDS database instances are encrypted",
        "description": "RDS data should be encrypted at rest using AWS KMS",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_17": {
        "id": "CIS AWS 2.3.2",
        "title": "Ensure RDS instance is not publicly accessible",
        "description": "RDS instances should not be accessible from the public internet",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_157": {
        "id": "CIS AWS 2.3.3",
        "title": "Ensure RDS database has IAM authentication enabled",
        "description": "IAM authentication provides centralized access control",
        "level": 2,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # IAM Issues
    "CKV_AWS_40": {
        "id": "CIS AWS 1.16",
        "title": "Ensure IAM policies are attached only to groups or roles",
        "description": "Policies should be attached to groups/roles, not directly to users",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "CKV_AWS_1": {
        "id": "CIS AWS 1.22",
        "title": "Ensure IAM policies do not allow full '*' administrative privileges",
        "description": "IAM policies should follow least privilege principle",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # Encryption Issues
    "CKV_AWS_7": {
        "id": "CIS AWS 2.8",
        "title": "Ensure rotation for customer created CMKs is enabled",
        "description": "KMS key rotation provides additional security for encrypted data",
        "level": 2,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # CloudTrail
    "CKV_AWS_35": {
        "id": "CIS AWS 3.1",
        "title": "Ensure CloudTrail is enabled in all regions",
        "description": "CloudTrail provides audit logging for all API calls",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },

    # Trivy specific mappings
    "AVD-AWS-0107": {
        "id": "CIS AWS 5.2",
        "title": "Security group allows unrestricted SSH access",
        "description": "SSH should be restricted to specific IP ranges",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "AVD-AWS-0102": {
        "id": "CIS AWS 2.1.5",
        "title": "S3 bucket does not have public access blocks",
        "description": "Public access blocks prevent data exposure",
        "level": 1,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
    "AVD-AWS-0086": {
        "id": "CIS AWS 2.1.2",
        "title": "S3 bucket does not have encryption enabled",
        "description": "S3 data should be encrypted at rest",
        "level": 2,
        "benchmark": "CIS AWS Foundations Benchmark v1.4.0"
    },
}
