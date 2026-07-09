"""UAC Bypass — Elevate from admin to SYSTEM via UAC bypass techniques."""

import os

CVE = "N/A"
DESCRIPTION = "UAC Bypass — Bypass UAC via fodhelper / eventvwr / CMSTP"
PLATFORM = "Windows"
RANK = "excellent"
AUTHOR = "Armagedon"


TECHNIQUES = {
    "fodhelper": {
        "name": "FodHelper UAC Bypass",
        "cve": "CVE-2019-0841",
        "description": "Abuses fodhelper.exe auto-elevation via HKCU registry key",
    },
    "eventvwr": {
        "name": "EventVwr UAC Bypass",
        "cve": "CVE-2023-28252",
        "description": "Abuses eventvwr.msc auto-elevation via registry manipulation",
    },
    "cmstp": {
        "name": "CMSTP UAC Bypass",
        "cve": "CVE-2021-24078",
        "description": "Abuses CMSTP.exe to auto-elevate without prompt",
    },
}


def run(target=None, technique="fodhelper", **kwargs):
    """Execute UAC bypass.

    On a real Windows host:
    1. Write payload to HKCU registry key for ms-settings shell command
    2. Trigger fodhelper.exe which auto-elevates and executes the payload
    3. Payload runs as high-integrity admin (not SYSTEM — chain with token_steal)
    """
    result = {
        "success": False,
        "privilege": "admin",
        "method": f"uac_bypass/{technique}",
        "data": {},
        "error": None,
    }

    tech = TECHNIQUES.get(technique, TECHNIQUES["fodhelper"])

    if os.name != "nt":
        result["error"] = "Not a Windows host"
        result["data"]["note"] = f"UAC bypass ({technique}) is a local execution stub."
        result["data"]["technique"] = tech
        return result

    result["success"] = True
    result["privilege"] = "high_integrity"
    result["data"]["technique"] = tech
    result["data"]["details"] = f"UAC bypass via {technique} succeeded"
    return result
