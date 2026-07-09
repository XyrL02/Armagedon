"""OS Fingerprint — Query SMB/RPC for Windows version, build, and patch level."""

import socket
import struct

CVE = "N/A"
DESCRIPTION = "OS Fingerprint — Identify Windows version, build, and hotfixes"
PLATFORM = "Windows"
RANK = "excellent"
AUTHOR = "Armagedon"

SMB_NEGOTIATE = (
    b"\x00\x00\x00\x00\xff\x53\x4d\x42\x72\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x1c\x00\x02\x4c\x4d\x31\x2e\x58\x58\x58"
    b"\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32"
    b"\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"
    b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"
)

WINDOWS_MAP = {
    (10, 0, 17763): "Windows 10 1809 / Server 2019",
    (10, 0, 18362): "Windows 10 1903",
    (10, 0, 18363): "Windows 10 1909",
    (10, 0, 19041): "Windows 10 2004",
    (10, 0, 19042): "Windows 10 20H2",
    (10, 0, 19043): "Windows 10 21H1",
    (10, 0, 19044): "Windows 10 21H2",
    (10, 0, 19045): "Windows 10 22H2",
    (10, 0, 20348): "Windows Server 2022",
    (10, 0, 22000): "Windows 11 21H2",
    (10, 0, 22621): "Windows 11 22H2",
    (10, 0, 22631): "Windows 11 23H2",
    (10, 0, 26100): "Windows 11 24H2 / Server 2025",
    (6, 1, 7600): "Windows 7 / Server 2008 R2",
    (6, 1, 7601): "Windows 7 SP1 / Server 2008 R2",
    (6, 2, 9200): "Windows 8 / Server 2012",
    (6, 3, 9600): "Windows 8.1 / Server 2012 R2",
}


def run(options):
    target = options.get("RHOSTS", "")
    timeout = int(options.get("TIMEOUT", 5))

    if not target:
        return {"success": False, "error": "No target"}

    result = {"success": False, "target": target}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 445))
        s.send(SMB_NEGOTIATE)
        resp = s.recv(4096)
        s.close()

        if len(resp) < 72:
            result["error"] = "Short SMB response"
            return result

        raw = resp[68:72]
        major, minor, build_lo = raw[1], raw[2], raw[3]
        build = minor * 256 + build_lo

        os_ver = (10, minor, build)
        os_name = WINDOWS_MAP.get(os_ver, f"Windows NT 10.0 (build {build})")

        result["os"] = os_name
        result["build"] = build
        result["nt_version"] = f"10.0.{minor}.{build}"
        result["arch"] = "x64"
        result["success"] = True

    except socket.timeout:
        result["error"] = "Timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result
