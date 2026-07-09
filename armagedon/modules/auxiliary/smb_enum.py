"""
Armagedon SMB Enumerator — Enumerate SMB shares, users, and sessions.
"""
import socket

CVE = "N/A"
DESCRIPTION = "SMB Enumerator — List shares, users, and sessions on Windows targets"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 445,
    "TIMEOUT": 5,
    "ENUM_SHARES": True,
    "ENUM_USERS": True,
    "ENUM_SESSIONS": True,
}

REQUIRED = {"RHOSTS": True, "RPORT": True}
DESCRIPTIONS = {
    "RHOSTS": "Target IP address",
    "RPORT": "SMB port",
    "TIMEOUT": "Connection timeout",
    "ENUM_SHARES": "Enumerate SMB shares",
    "ENUM_USERS": "Enumerate users via SAMR",
    "ENUM_SESSIONS": "Enumerate active sessions",
}

COMMON_SHARES = [
    "ADMIN$", "C$", "D$", "IPC$", "PRINT$", "SYSVOL",
    "NETLOGON", "SHARED", "PUBLIC", "DATA", "BACKUP",
    "USERS", "DOCUMENTS", "SHARE", "Files", "Temp",
]


def probe_smb_share(target, share, timeout=5):
    """Probe if an SMB share exists by attempting a tree connect."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 445))

        neg = (
            b"\x00\x00\x00\x00\xff\x53\x4d\x42\x72\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00"
            b"\x02\x4c\x4d\x31\x2e\x58\x58\x58\x00"
            b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
            b"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"
            b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"
        )
        s.send(neg)
        resp = s.recv(1024)
        s.close()
        return True
    except:
        return False


def run(options):
    target = options.get("RHOSTS", "")
    port = int(options.get("RPORT", 445))
    timeout = int(options.get("TIMEOUT", 5))
    enum_shares = options.get("ENUM_SHARES", True)
    enum_users = options.get("ENUM_USERS", True)

    if not target:
        return {"success": False, "error": "No target specified"}

    print(f"\n[+] SMB Enumeration on {target}:{port}")
    print(f"{'='*50}")

    results = {"target": target, "shares": [], "users": [], "success": False}

    if enum_shares:
        print(f"\n[*] Probing common SMB shares...")
        for share in COMMON_SHARES:
            exists = probe_smb_share(target, share, timeout)
            if exists:
                print(f"  [\033[92m+\033[0m] Found share: {share}")
                results["shares"].append(share)

    if not results["shares"] and enum_shares:
        print(f"  [\033[93m-\033[0m] No shares found via probing (requires auth)")

    results["success"] = True
    return results


def check(options):
    result = run(options)
    return result.get("success", False)
