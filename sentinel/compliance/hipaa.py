"""HIPAA Security Rule mappings for common security checks."""

# HIPAA Security Rule mappings for infrastructure security checks
HIPAA_CONTROL_MAP = {
    # Access Control - 164.312(a)(1)
    "CKV_AWS_23": {
        "control": "164.312(a)(1)",
        "title": "Access Control",
        "requirement": "Implement technical policies and procedures for electronic information systems that maintain ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Unique User Identification, Emergency Access Procedure, Automatic Logoff, Encryption and Decryption"
    },
    "CKV_AWS_24": {
        "control": "164.312(a)(1)",
        "title": "Access Control",
        "requirement": "Implement technical policies and procedures for electronic information systems that maintain ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Restrict administrative access to authorized personnel only"
    },
    "CKV_AWS_25": {
        "control": "164.312(a)(1)",
        "title": "Access Control",
        "requirement": "Implement technical policies and procedures for electronic information systems that maintain ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Restrict access to systems containing ePHI"
    },

    # Audit Controls - 164.312(b)
    "CKV_AWS_18": {
        "control": "164.312(b)",
        "title": "Audit Controls",
        "requirement": "Implement hardware, software, and/or procedural mechanisms that record and examine activity",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable access logging for systems containing ePHI"
    },
    "CKV_AWS_35": {
        "control": "164.312(b)",
        "title": "Audit Controls",
        "requirement": "Implement hardware, software, and/or procedural mechanisms that record and examine activity",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable comprehensive audit logging across all regions"
    },

    # Integrity - 164.312(c)(1)
    "CKV_AWS_21": {
        "control": "164.312(c)(1)",
        "title": "Integrity",
        "requirement": "Implement policies and procedures to protect ePHI from improper alteration or destruction",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable versioning for data protection and recovery"
    },

    # Transmission Security - 164.312(e)(1)
    "CKV_AWS_19": {
        "control": "164.312(e)(1)",
        "title": "Transmission Security",
        "requirement": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over network",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable encryption at rest for ePHI data"
    },
    "CKV_AWS_16": {
        "control": "164.312(e)(1)",
        "title": "Transmission Security",
        "requirement": "Implement technical security measures to guard against unauthorized access to ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Encrypt database containing ePHI at rest"
    },

    # Person or Entity Authentication - 164.312(d)
    "CKV_AWS_157": {
        "control": "164.312(d)",
        "title": "Person or Entity Authentication",
        "requirement": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable IAM authentication for database access"
    },

    # Workstation Security - 164.310(c)
    "CKV_AWS_17": {
        "control": "164.310(c)",
        "title": "Workstation Security",
        "requirement": "Implement physical safeguards for all workstations that access ePHI",
        "safeguard": "Physical Safeguard",
        "implementation": "Restrict database access to private networks only"
    },

    # Access Authorization - 164.312(a)(2)(i)
    "CKV_AWS_1": {
        "control": "164.312(a)(2)(i)",
        "title": "Unique User Identification",
        "requirement": "Assign a unique name and/or number for identifying and tracking user identity",
        "safeguard": "Technical Safeguard",
        "implementation": "Implement least privilege access policies"
    },
    "CKV_AWS_40": {
        "control": "164.312(a)(2)(i)",
        "title": "Unique User Identification",
        "requirement": "Assign a unique name and/or number for identifying and tracking user identity",
        "safeguard": "Technical Safeguard",
        "implementation": "Use groups and roles for access management"
    },

    # Data Backup - 164.308(a)(7)(ii)(A)
    "CKV_AWS_20": {
        "control": "164.308(a)(7)(ii)(A)",
        "title": "Data Backup Plan",
        "requirement": "Establish and implement procedures to create and maintain retrievable exact copies of ePHI",
        "safeguard": "Administrative Safeguard",
        "implementation": "Prevent accidental public exposure of ePHI backups"
    },
    "CKV2_AWS_6": {
        "control": "164.308(a)(7)(ii)(A)",
        "title": "Data Backup Plan",
        "requirement": "Establish and implement procedures to create and maintain retrievable exact copies of ePHI",
        "safeguard": "Administrative Safeguard",
        "implementation": "Block public access to storage containing ePHI"
    },

    # Encryption Key Management - 164.312(a)(2)(iv)
    "CKV_AWS_7": {
        "control": "164.312(a)(2)(iv)",
        "title": "Encryption and Decryption",
        "requirement": "Implement a mechanism to encrypt and decrypt ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable key rotation for encryption keys"
    },

    # Trivy mappings
    "AVD-AWS-0107": {
        "control": "164.312(a)(1)",
        "title": "Access Control",
        "requirement": "Implement technical policies and procedures for electronic information systems",
        "safeguard": "Technical Safeguard",
        "implementation": "Restrict SSH access to authorized networks"
    },
    "AVD-AWS-0102": {
        "control": "164.308(a)(7)(ii)(A)",
        "title": "Data Backup Plan",
        "requirement": "Establish and implement procedures to protect ePHI",
        "safeguard": "Administrative Safeguard",
        "implementation": "Block public access to storage"
    },
    "AVD-AWS-0086": {
        "control": "164.312(e)(1)",
        "title": "Transmission Security",
        "requirement": "Implement technical security measures for ePHI",
        "safeguard": "Technical Safeguard",
        "implementation": "Enable encryption at rest"
    },
}
