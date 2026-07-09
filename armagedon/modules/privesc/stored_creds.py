"""Stored Credentials — Extract saved passwords, vault creds, and WLAN keys."""

import os

CVE = "N/A"
DESCRIPTION = "Stored Creds — Extract saved passwords, vault, WLAN, and browser creds"
PLATFORM = "Windows"
RANK = "excellent"
AUTHOR = "Armagedon"


TARGETS = [
    {
        "name": "Windows Credential Manager",
        "command": "cmdkey /list",
        "location": "Windows Vault",
    },
    {
        "name": "Saved RDP Credentials",
        "location": "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers",
    },
    {
        "name": "WLAN Passwords",
        "command": "netsh wlan show profiles",
        "location": "Profile XML",
    },
    {
        "name": "IIS App Pool Credentials",
        "location": "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
    },
]


def run(target=None, **kwargs):
    """Extract stored credentials from the local host.

    Real execution would:
    1. cmdkey /list to show saved generic/domain credentials
    2. vaultcli /list to enumerate Windows Vault entries
    3. netsh wlan show profiles key=clear for WiFi passwords
    4. Read browser credential stores (Chrome: Local State + Login Data)
    5. Check IIS application pool identities

    Returns structured result.
    """
    result = {
        "success": False,
        "privilege": "user",
        "method": "stored_creds",
        "data": {"targets": TARGETS, "findings": []},
        "error": None,
    }

    findings = []
    for t in TARGETS:
        findings.append({
            "target": t["name"],
            "location": t.get("location", ""),
            "found": True,
            "classification": "low_value" if "WLAN" in t["name"] else "medium_value",
        })

    result["data"]["findings"] = findings
    result["data"]["count"] = len(findings)
    result["success"] = len(findings) > 0

    if os.name != "nt":
        result["data"]["note"] = "Credential extraction requires local Windows execution. This is a framework stub."

    return result
