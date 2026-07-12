"""OS, service, and patch fingerprint database.
Maps scan findings to exploit applicability."""

import logging
import re

log = logging.getLogger("armagedon.core.fingerprints")

OS_SIGNATURES = {
    "Windows 10 22H2": {
        "patterns": [r"10\.0\.1904[5-6]"],
        "build_min": 19045,
        "build_max": 19046,
        "nt": "10.0",
    },
    "Windows 11 23H2": {
        "patterns": [r"10\.0\.2263[1-5]"],
        "build_min": 22631,
        "build_max": 22635,
        "nt": "10.0",
    },
    "Windows 11 24H2": {
        "patterns": [r"10\.0\.26100"],
        "build_min": 26100,
        "build_max": 26101,
        "nt": "10.0",
    },
    "Windows Server 2022": {
        "patterns": [r"10\.0\.2034[8-9]"],
        "build_min": 20348,
        "build_max": 20349,
        "nt": "10.0",
    },
    "Windows Server 2025": {
        "patterns": [r"10\.0\.26100"],
        "build_min": 26100,
        "build_max": 26101,
        "nt": "10.0",
    },
    "Windows 8.1": {
        "patterns": [r"6\.3\.9600"],
        "build_min": 9600,
        "build_max": 9601,
        "nt": "6.3",
    },
    "Windows Server 2016": {
        "patterns": [r"10\.0\.1439[3-4]"],
        "build_min": 14393,
        "build_max": 14394,
        "nt": "10.0",
    },
    "Windows Server 2019": {
        "patterns": [r"10\.0\.1776[3-4]"],
        "build_min": 17763,
        "build_max": 17764,
        "nt": "10.0",
    },
}


def identify_os(build_number: int, nt_version: str = "") -> list:
    """Return possible OS names matching a build number."""
    log.info("identify_os: build=%d nt=%s", build_number, nt_version)
    matches = []
    for name, info in OS_SIGNATURES.items():
        if info["build_min"] <= build_number <= info["build_max"]:
            matches.append(name)
        elif nt_version and info["nt"] == nt_version:
            matches.append(name)
    log.debug("identify_os: build=%d nt=%s → %s", build_number, nt_version, matches)
    return matches


def build_to_cpe(build_number: int) -> str:
    """Map Windows build to a CPE-like string for matching."""
    for name, info in OS_SIGNATURES.items():
        if info["build_min"] <= build_number <= info["build_max"]:
            ver = name.lower().replace(" ", "_")
            cpe = f"cpe:/o:microsoft:{ver}"
            log.debug("build_to_cpe: %d → %s", build_number, cpe)
            return cpe
    return f"cpe:/o:microsoft:windows_unknown"


SERVICE_VULN_MAP = {
    135: {
        "service": "MSRPC",
        "exploit_classes": ["rpc", "dcom", "lsass"],
        "cvss_range": (7.5, 9.8),
    },
    139: {
        "service": "NetBIOS",
        "exploit_classes": ["smb", "netbios"],
        "cvss_range": (5.0, 8.0),
    },
    445: {
        "service": "SMB",
        "exploit_classes": ["smb", "smb2", "eternalblue", "zerologon", "petitpotam"],
        "cvss_range": (6.5, 9.8),
    },
    3389: {
        "service": "RDP",
        "exploit_classes": ["rdp", "bluekeep", "rdp_mitm"],
        "cvss_range": (7.0, 9.8),
    },
    5985: {
        "service": "WinRM (HTTP)",
        "exploit_classes": ["winrm", "ps_remoting"],
        "cvss_range": (6.0, 8.0),
    },
    5986: {
        "service": "WinRM (HTTPS)",
        "exploit_classes": ["winrm", "ps_remoting"],
        "cvss_range": (6.0, 8.0),
    },
    389: {
        "service": "LDAP",
        "exploit_classes": ["ldap", "adcs", "zerologon"],
        "cvss_range": (6.5, 9.8),
    },
    636: {
        "service": "LDAPS",
        "exploit_classes": ["ldap", "adcs"],
        "cvss_range": (6.5, 9.8),
    },
    88: {
        "service": "Kerberos",
        "exploit_classes": ["kerberos", "krb_relay", "golden_ticket"],
        "cvss_range": (7.0, 9.0),
    },
    464: {
        "service": "Kerberos (UDP)",
        "exploit_classes": ["kerberos"],
        "cvss_range": (7.0, 9.0),
    },
    593: {
        "service": "HTTP RPC Endpoint Mapper",
        "exploit_classes": ["rpc", "http_rpc"],
        "cvss_range": (6.0, 8.0),
    },
}


PROTOCOL_VULN_MAP = {
    "SMB1": {
        "enabled": True,
        "exploit_classes": ["eternalblue", "wannacry", "smbghost"],
        "risk": "critical",
    },
    "SMB2": {
        "enabled": True,
        "exploit_classes": ["zerologon", "smbghost"],
        "risk": "high",
    },
    "SMB signing": {
        "enabled": False,
        "exploit_classes": ["ntlm_relay", "smb_relay"],
        "risk": "medium",
    },
}


PATCH_BLACKLIST = {
    "KB5034441": {
        "cve": "CVE-2024-20666",
        "description": "BitLocker Bypass",
        "cvss": 6.6,
        "os": ["Windows 10", "Windows 11"],
    },
}


EXPLOIT_METADATA = {
    "cve_2024_38077_madlicense_eop": {
        "cve": "CVE-2024-38077",
        "name": "MadLicense — Windows RDL Service Heap Overflow",
        "cvss": 9.8,
        "type": "rce",
        "port": 135,
        "service": "MSRPC",
        "os": ["Windows Server 2003-2025"],
        "auth": False,
        "description": "Pre-auth heap overflow in CDataCoding::DecodeData; SYSTEM level",
    },
    "cve_2024_43641_ffi_registry_eop": {
        "cve": "CVE-2024-43641",
        "name": "Windows Registry FFI EoP",
        "cvss": 7.8,
        "type": "eop",
        "port": None,
        "service": "local",
        "os": ["Windows 10+", "Windows Server 2019+"],
        "auth": True,
        "description": "Registry-flip phishing EoP",
    },
    "cve_2024_21338_appid_privesc": {
        "cve": "CVE-2024-21338",
        "name": "AppID LPE — Kernel Use-After-Free",
        "cvss": 7.8,
        "type": "eop",
        "port": None,
        "service": "local",
        "os": ["Windows 10 1803+", "Windows 11"],
        "auth": True,
        "description": "Kernel use-after-free in appid.sys; SYSTEM escalation",
    },
    "cve_2024_26234_proxydriver_spoof": {
        "cve": "CVE-2024-26234",
        "name": "Proxy Driver Spoofing",
        "cvss": 7.5,
        "type": "auth_bypass",
        "port": None,
        "service": "local",
        "os": ["Windows 10", "Windows 11", "Windows Server 2022"],
        "auth": True,
        "description": "Hardware driver key spoofing; signature bypass",
    },
    "cve_2024_26229_csc_lpe": {
        "cve": "CVE-2024-26229",
        "name": "CSC Service LPE",
        "cvss": 7.8,
        "type": "eop",
        "port": None,
        "service": "local",
        "os": ["Windows 10 1809+", "Windows Server 2019+"],
        "auth": True,
        "description": "Windows CSC Service elevation; directory traversal to SYSTEM",
    },
    "cve_2025_21217_win_kernel_lpe": {
        "cve": "CVE-2025-21217",
        "name": "Windows Kernel LPE",
        "cvss": 7.8,
        "type": "eop",
        "port": None,
        "service": "local",
        "os": ["Windows 11 23H2", "Windows Server 2025"],
        "auth": True,
        "description": "Kernel type confusion; low-priv to SYSTEM",
    },
}
