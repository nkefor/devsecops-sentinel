"""PCI-DSS v4.0 mappings for common security checks."""

# PCI-DSS v4.0 mappings for infrastructure security checks
PCI_DSS_MAP = {
    # Requirement 1: Install and Maintain Network Security Controls
    "CKV_AWS_23": {
        "requirement": "1.2.1",
        "title": "Restrict inbound and outbound traffic",
        "description": "Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment",
        "category": "Build and Maintain a Secure Network and Systems"
    },
    "CKV_AWS_24": {
        "requirement": "1.2.1",
        "title": "Restrict inbound and outbound traffic",
        "description": "Restrict RDP access to necessary personnel only",
        "category": "Build and Maintain a Secure Network and Systems"
    },
    "CKV_AWS_25": {
        "requirement": "1.3.1",
        "title": "Restrict access to CDE",
        "description": "Restrict access to system components in the cardholder data environment",
        "category": "Build and Maintain a Secure Network and Systems"
    },
    "CKV_AWS_17": {
        "requirement": "1.3",
        "title": "Prohibit direct public access",
        "description": "Prohibit direct public access between the internet and any system component in the CDE",
        "category": "Build and Maintain a Secure Network and Systems"
    },

    # Requirement 3: Protect Stored Account Data
    "CKV_AWS_19": {
        "requirement": "3.4",
        "title": "Render PAN unreadable",
        "description": "Render PAN unreadable anywhere it is stored using strong cryptography",
        "category": "Protect Cardholder Data"
    },
    "CKV_AWS_16": {
        "requirement": "3.4",
        "title": "Render PAN unreadable",
        "description": "Encrypt cardholder data at rest in databases",
        "category": "Protect Cardholder Data"
    },
    "CKV_AWS_7": {
        "requirement": "3.6.4",
        "title": "Cryptographic key changes",
        "description": "Cryptographic keys must be changed when they have reached the end of their cryptoperiod",
        "category": "Protect Cardholder Data"
    },

    # Requirement 7: Restrict Access to System Components
    "CKV_AWS_20": {
        "requirement": "7.1",
        "title": "Limit access to system components",
        "description": "Limit access to system components and cardholder data to those whose job requires it",
        "category": "Implement Strong Access Control Measures"
    },
    "CKV2_AWS_6": {
        "requirement": "7.1",
        "title": "Limit access to system components",
        "description": "Block public access to storage containing cardholder data",
        "category": "Implement Strong Access Control Measures"
    },
    "CKV_AWS_1": {
        "requirement": "7.1",
        "title": "Limit access to system components",
        "description": "Restrict system access to the minimum necessary for job functions",
        "category": "Implement Strong Access Control Measures"
    },
    "CKV_AWS_40": {
        "requirement": "7.2",
        "title": "Access control systems",
        "description": "Establish an access control system for system components",
        "category": "Implement Strong Access Control Measures"
    },

    # Requirement 8: Identify Users and Authenticate Access
    "CKV_AWS_157": {
        "requirement": "8.3",
        "title": "Strong authentication",
        "description": "Establish and manage strong authentication for users and administrators",
        "category": "Implement Strong Access Control Measures"
    },

    # Requirement 10: Log and Monitor All Access
    "CKV_AWS_18": {
        "requirement": "10.2",
        "title": "Audit logs",
        "description": "Implement automated audit trails for all system components",
        "category": "Regularly Monitor and Test Networks"
    },
    "CKV_AWS_35": {
        "requirement": "10.1",
        "title": "Audit trails",
        "description": "Implement audit trails to link all access to individual users",
        "category": "Regularly Monitor and Test Networks"
    },
    "CKV_AWS_21": {
        "requirement": "10.7",
        "title": "Retain audit trail history",
        "description": "Retain audit trail history for at least one year",
        "category": "Regularly Monitor and Test Networks"
    },

    # Trivy mappings
    "AVD-AWS-0107": {
        "requirement": "1.2.1",
        "title": "Restrict inbound and outbound traffic",
        "description": "Restrict SSH access to necessary IP ranges only",
        "category": "Build and Maintain a Secure Network and Systems"
    },
    "AVD-AWS-0102": {
        "requirement": "7.1",
        "title": "Limit access to system components",
        "description": "Block public access to storage",
        "category": "Implement Strong Access Control Measures"
    },
    "AVD-AWS-0086": {
        "requirement": "3.4",
        "title": "Render PAN unreadable",
        "description": "Enable encryption at rest for data storage",
        "category": "Protect Cardholder Data"
    },
}
