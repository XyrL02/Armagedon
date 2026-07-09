"""
Armagedon SMB Scanner — Detect SMB version, OS, shares, and vulnerabilities.
"""
import socket
import struct

CVE = "N/A"
DESCRIPTION = "SMB Scanner — Enumerate Windows targets via SMB protocol"
PLATFORM = "Windows"
RANK = "excellent"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 445,
    "TIMEOUT": 5,
    "VERBOSE": True,
}

REQUIRED = {"RHOSTS": True, "RPORT": True}
DESCRIPTIONS = {
    "RHOSTS": "Target IP address",
    "RPORT": "SMB port (default: 445)",
    "TIMEOUT": "Connection timeout in seconds",
    "VERBOSE": "Enable verbose output",
}

SMB_NEGOTIATE_PROTOCOL = (
    b"\x00\x00\x00\x00"  # SMB Header
    b"\xff\x53\x4d\x42"  # Server Component: SMB
    b"\x72\x00\x00\x00"  # SMB Command: Negotiate Protocol
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Status
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Flags
    b"\x00\x00\x00\x00\x00\x00"  # PID, UID, MID
    b"\x00\x00"  # Word Count
    b"\x1c\x00"  # Byte Count
    b"\x02\x4c\x4d\x31\x2e\x58\x58\x58\x00"  # LM1.2X
    b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12
    b"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"  # SMB 2.002
    b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"  # SMB 2.???
)

WINDOWS_VERSIONS = {
    (10, 0, 10240): "Windows 10 1507",
    (10, 0, 10586): "Windows 10 1511",
    (10, 0, 14393): "Windows 10 1607 / Server 2016",
    (10, 0, 15063): "Windows 10 1703",
    (10, 0, 16299): "Windows 10 1709",
    (10, 0, 17134): "Windows 10 1803",
    (10, 0, 17763): "Windows 10 1809 / Server 2019",
    (10, 0, 18362): "Windows 10 1903",
    (10, 0, 18363): "Windows 10 1909",
    (10, 0, 19041): "Windows 10 2004 / 20H1",
    (10, 0, 19042): "Windows 10 20H2",
    (10, 0, 19043): "Windows 10 21H1",
    (10, 0, 19044): "Windows 10 21H2",
    (10, 0, 19045): "Windows 10 22H2",
    (10, 0, 20348): "Windows Server 2022",
    (10, 0, 22000): "Windows 11 21H2",
    (10, 0, 22621): "Windows 11 22H2",
    (10, 0, 22631): "Windows 11 23H2",
    (10, 0, 26100): "Windows 11 24H2 / Server 2025",
    (5, 1, 2600): "Windows XP",
    (5, 2, 3790): "Windows Server 2003",
    (6, 0, 6000): "Windows Vista",
    (6, 0, 6001): "Windows Server 2008",
    (6, 1, 7600): "Windows 7 / Server 2008 R2",
    (6, 1, 7601): "Windows 7 SP1 / Server 2008 R2",
    (6, 2, 9200): "Windows 8 / Server 2012",
    (6, 3, 9200): "Windows 8.1 / Server 2012 R2",
    (6, 3, 9600): "Windows 8.1 / Server 2012 R2",
}

SMB_VULNERABILITY_SIGNATURES = {
    "MS17-010": {
        "name": "EternalBlue",
        "cve": "CVE-2017-0143",
        "check": lambda ver: ver <= (10, 0, 14393),
        "severity": "CRITICAL",
    },
    "Zerologon": {
        "name": "Zerologon",
        "cve": "CVE-2020-1472",
        "check": lambda ver: (6, 1, 0) <= ver <= (10, 0, 20348),
        "severity": "CRITICAL",
    },
    "PrintNightmare": {
        "name": "PrintNightmare",
        "cve": "CVE-2021-34527",
        "check": lambda ver: ver >= (10, 0, 10240),
        "severity": "CRITICAL",
    },
    "PetitPotam": {
        "name": "PetitPotam",
        "cve": "CVE-2021-36942",
        "check": lambda ver: (6, 1, 0) <= ver <= (10, 0, 22000),
        "severity": "HIGH",
    },
    "NoPac": {
        "name": "SamAccountName Spoofing",
        "cve": "CVE-2021-42278 / CVE-2021-42287",
        "check": lambda ver: (6, 1, 0) <= ver <= (10, 0, 20348),
        "severity": "CRITICAL",
    },
    "DFSCoC": {
        "name": "DFSCoC",
        "cve": "CVE-2023-24903",
        "check": lambda ver: ver >= (10, 0, 10240),
        "severity": "MEDIUM",
    },
}


def run(options):
    target = options.get("RHOSTS", "")
    port = int(options.get("RPORT", 445))
    timeout = int(options.get("TIMEOUT", 5))
    verbose = options.get("VERBOSE", True)

    if not target:
        return {"success": False, "error": "No target specified"}

    result = {"success": False, "target": target, "port": port}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.send(SMB_NEGOTIATE_PROTOCOL)
        resp = s.recv(4096)
        s.close()

        if len(resp) < 72:
            result["error"] = "Invalid SMB response"
            return result

        result["smb_detected"] = True

        smb_version_raw = resp[68:72]
        smb_major = smb_version_raw[1]
        smb_minor = smb_version_raw[2]
        smb_build_lo = smb_version_raw[3]

        os_version_tuple = (10, smb_major, smb_minor * 256 + smb_build_lo)
        os_version_tuple_fallback = (10, smb_major, smb_minor)

        os_name = WINDOWS_VERSIONS.get(
            os_version_tuple,
            WINDOWS_VERSIONS.get(
                os_version_tuple_fallback,
                f"Windows (10.0.{smb_major}.{smb_minor * 256 + smb_build_lo})"
            )
        )

        result["os"] = os_name
        result["os_version_tuple"] = list(os_version_tuple)
        result["smb_version"] = f"10.0.{smb_major}.{smb_minor * 256 + smb_build_lo}"

        if verbose:
            print(f"[+] Target: {target}")
            print(f"[+] OS Detected: {os_name}")
            print(f"[+] SMB Version: 10.0.{smb_major}.{smb_minor} (build {smb_minor * 256 + smb_build_lo})")

        vulns = []
        for vuln_key, vuln_info in SMB_VULNERABILITY_SIGNATURES.items():
            if vuln_info["check"](os_version_tuple):
                vulns.append({
                    "name": vuln_info["name"],
                    "cve": vuln_info["cve"],
                    "severity": vuln_info["severity"],
                })
                if verbose:
                    sev_color = "\033[91m" if vuln_info["severity"] == "CRITICAL" else "\033[93m"
                    print(f"  {sev_color}[!] Potential: {vuln_info['name']} ({vuln_info['cve']}) - {vuln_info['severity']}\033[0m")

        result["vulnerabilities"] = vulns
        result["vulnerability_count"] = len(vulns)
        result["success"] = True

        if verbose:
            print(f"\n[+] Total potential vulnerabilities: {len(vulns)}")

    except socket.timeout:
        result["error"] = f"Connection to {target}:{port} timed out"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on {target}:{port}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check(options):
    result = run(options)
    return result.get("success", False) and result.get("vulnerability_count", 0) > 0
