"""
Armagedon SMB Scanner — Detect SMB version, OS, shares, and vulnerabilities.
"""
import socket
import struct
import re

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


def _parse_native_os(resp: bytes) -> dict:
    """Parse the NativeOS string from SMB1 negotiate response to extract Windows version.

    The NativeOS field appears after the security buffer in the SMB1 negotiate response.
    Format: 'Windows 10.0.19041' or 'Windows NT 6.1' etc.
    Returns dict with 'os', 'build', 'major', 'minor', 'raw' keys.
    """
    result = {"os": "", "build": 0, "major": 0, "minor": 0, "raw": ""}

    # The NativeOS string follows the SecurityBlob in SMB1 negotiate response.
    # We look for "Windows" followed by version info anywhere in the response.
    try:
        # Decode the response as latin-1 to preserve all bytes
        raw_str = resp.decode("latin-1", errors="ignore")

        # Match patterns like "Windows 10.0.19041" or "Windows NT 6.1.7601"
        # The NativeOS field in SMB1 typically contains: "Windows <major>.<minor>.<build>"
        patterns = [
            r"Windows\s+(?:NT\s+)?(\d+)\.(\d+)\.(\d+)",  # Windows 10.0.19041
            r"Windows\s+(\d+)\.(\d+)\.(\d+)",              # Windows 6.1.7601
            r"Windows\s+NT\s+(\d+)\.(\d+)",                 # Windows NT 6.1
        ]

        for pat in patterns:
            match = re.search(pat, raw_str)
            if match:
                groups = match.groups()
                major = int(groups[0])
                minor = int(groups[1])
                build = int(groups[2]) if len(groups) > 2 else 0
                result["os"] = match.group(0)
                result["major"] = major
                result["minor"] = minor
                result["build"] = build
                result["raw"] = match.group(0)
                return result

        # Fallback: try to find version info in the binary data after security buffer
        # SMB1 negotiate response: header(32) + wordcount(1) + bytecount(2) + security_blob + NativeOS
        if len(resp) > 36:
            word_count = resp[32]
            byte_count = struct.unpack_from("<H", resp, 33)[0] if len(resp) >= 35 else 0
            native_os_offset = 36 + word_count + byte_count
            if native_os_offset < len(resp):
                native_os_raw = resp[native_os_offset:]
                # Find null-terminated strings
                strings = []
                current = []
                for b in native_os_raw:
                    if b == 0:
                        if current:
                            try:
                                strings.append(bytes(current).decode("latin-1", errors="ignore"))
                            except:
                                pass
                            current = []
                    else:
                        current.append(b)

                for s in strings:
                    match = re.search(r"Windows\s+(?:NT\s+)?(\d+)\.(\d+)\.(\d+)", s)
                    if match:
                        groups = match.groups()
                        result["os"] = match.group(0)
                        result["major"] = int(groups[0])
                        result["minor"] = int(groups[1])
                        result["build"] = int(groups[2])
                        result["raw"] = s.strip()
                        return result
    except Exception:
        pass

    return result

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


class SMBScanner:
    """Class-based scanner for programmatic use by the pipeline."""

    def scan_port(self, target: str, port: int, timeout: int = 5) -> dict:
        """Probe a single TCP port and return basic info."""
        info = {"port": port, "open": False, "service": "", "banner": ""}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            info["open"] = True
            s.close()
        except Exception:
            info["open"] = False
        return info

    def quick_scan(self, target: str, ports: str = "135,139,445,3389,5985,5986,389,88,593") -> dict:
        """Multi-port probe returning structured data for the recommender."""
        results = {
            "open_ports": [],
            "services": {},
            "os": "",
            "build": 0,
            "protocols": {},
            "hotfixes": [],
            "smb_info": {},
            "raw": {},
        }

        port_list = [int(p) for p in ports.split(",") if p.strip().isdigit()]

        for port in port_list:
            info = self.scan_port(target, port)
            if info["open"]:
                results["open_ports"].append(port)

        if 445 in results["open_ports"] or 139 in results["open_ports"]:
            smb_result = run({"RHOSTS": target, "RPORT": 445, "TIMEOUT": 5, "VERBOSE": False})
            if smb_result.get("success"):
                results["os"] = smb_result.get("os", "")
                results["build"] = smb_result.get("build", 0)
                results["smb_info"] = {
                    "version": smb_result.get("smb_version", ""),
                    "detected": True,
                }
                if smb_result.get("vulnerabilities"):
                    results["protocols"]["smb_vulns"] = smb_result["vulnerabilities"]

        return results


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

        # Parse OS from NativeOS string in the negotiate response
        native_os = _parse_native_os(resp)

        if native_os["os"]:
            os_name = native_os["os"]
            os_version_tuple = (native_os["major"], native_os["minor"], native_os["build"])
        else:
            # Fallback: try the original binary extraction
            smb_version_raw = resp[68:72]
            smb_major = smb_version_raw[1]
            smb_minor = smb_version_raw[2]
            smb_build_lo = smb_version_raw[3]
            os_version_tuple = (10, smb_major, smb_minor * 256 + smb_build_lo)
            os_name = WINDOWS_VERSIONS.get(
                os_version_tuple,
                WINDOWS_VERSIONS.get(
                    (10, smb_major, smb_minor),
                    f"Windows (10.0.{smb_major}.{smb_minor * 256 + smb_build_lo})"
                )
            )

        result["os"] = os_name
        result["os_version_tuple"] = list(os_version_tuple)
        result["build"] = native_os["build"] if native_os["build"] else os_version_tuple[2]
        result["smb_version"] = f"{os_version_tuple[0]}.{os_version_tuple[1]}.{result['build']}"

        if verbose:
            print(f"[+] Target: {target}")
            print(f"[+] OS Detected: {os_name}")
            print(f"[+] SMB Version: {result['smb_version']} (build {result['build']})")

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
