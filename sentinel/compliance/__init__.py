"""Compliance framework mappings for DevSecOps Sentinel."""
from .cis import CIS_BENCHMARK_MAP
from .hipaa import HIPAA_CONTROL_MAP
from .pci_dss import PCI_DSS_MAP

__all__ = [
    'CIS_BENCHMARK_MAP',
    'HIPAA_CONTROL_MAP',
    'PCI_DSS_MAP',
    'get_compliance_mapping',
]


def get_compliance_mapping(check_id: str) -> dict:
    """
    Get all compliance mappings for a given check ID.

    Args:
        check_id: The scanner check ID

    Returns:
        Dictionary with all compliance framework mappings
    """
    return {
        "cis": CIS_BENCHMARK_MAP.get(check_id, {}),
        "hipaa": HIPAA_CONTROL_MAP.get(check_id, {}),
        "pci_dss": PCI_DSS_MAP.get(check_id, {}),
    }
