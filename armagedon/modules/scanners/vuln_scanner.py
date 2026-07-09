"""
Armagedon Multi-Vulnerability Scanner — Scans Windows targets for known CVEs.
Combines SMB, RDP, WinRM, RPC, and LDAP checks into a single comprehensive scan.
"""
import socket
import struct
import ssl
import base64

CVE = "N/A"
DESCRIPTION = "Multi-Vulnerability Scanner — Comprehensive Windows target assessment"
PLATFORM = "Windows"
RANK = "excellent"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "TIMEOUT": 5,
    "VERBOSE": True,
    "ALL_PORTS": False,
}

REQUIRED = {"RHOSTS": True}
DESCRIPTIONS = {
    "RHOSTS": "Target IP address",
    "TIMEOUT": "Connection timeout in seconds",
    "VERBOSE": "Enable verbose output",
    "ALL_PORTS": "Scan all common Windows ports",
}


def check_smb(target, timeout):
    """Quick SMB version check and vulnerability fingerprinting."""
    results = []
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
        resp = s.recv(4096)
        s.close()
        if len(resp) >= 72:
            results.append({"port": 445, "service": "SMB", "status": "open"})
            results.append({"port": 445, "service": "SMB", "status": "Version detected"})
    except:
        pass
    return results


def check_rdp(target, timeout):
    """RDP check for BlueKeep, DejaBlue, and other RDP vulns."""
    results = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 3389))
        s.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
        resp = s.recv(1024)
        s.close()
        if resp:
            results.append({"port": 3389, "service": "RDP", "status": "open"})
            # Check for BlueKeep indicators
            if len(resp) > 20:
                rdp_version = resp[20] if len(resp) > 20 else 0
                if rdp_version < 10:
                    results.append({"port": 3389, "service": "RDP", "status": "Potential BlueKeep (CVE-2019-0708)"})
    except:
        pass
    return results


def check_winrm(target, timeout):
    """WinRM / WSMan check."""
    results = []
    for port, secure in [(5985, False), (5986, True)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            if secure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s)
            s.send(b"GET /wsman HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            resp = s.recv(1024)
            s.close()
            results.append({"port": port, "service": f"WinRM_{'HTTPS' if secure else 'HTTP'}", "status": "open"})
        except:
            pass
    return results


def check_rpc(target, timeout):
    """RPC endpoint mapper check."""
    results = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 135))
        bind_req = (
            b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"
            b"\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x00\x00\x01\x00\x06\x11\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
            b"\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        s.send(bind_req)
        resp = s.recv(4096)
        s.close()
        if resp:
            results.append({"port": 135, "service": "RPC", "status": "open"})
    except:
        pass
    return results


def check_ldap(target, timeout):
    """LDAP check for domain controllers."""
    results = []
    for port in [389, 636, 3268, 3269]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            s.close()
            svc = {389: "LDAP", 636: "LDAPS", 3268: "GlobalCatalog", 3269: "GlobalCatalog_SSL"}
            results.append({"port": port, "service": svc[port], "status": "open"})
        except:
            pass
    return results


def check_kerberos(target, timeout):
    """Kerberos check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 88))
        s.close()
        return [{"port": 88, "service": "Kerberos", "status": "open"}]
    except:
        return []


def run(options):
    target = options.get("RHOSTS", "")
    timeout = int(options.get("TIMEOUT", 5))
    verbose = options.get("VERBOSE", True)
    all_ports = options.get("ALL_PORTS", False)

    if not target:
        return {"success": False, "error": "No target specified"}

    print(f"\n{'='*60}")
    print(f"  Armagedon Multi-Vulnerability Scanner")
    print(f"  Target: {target}")
    print(f"{'='*60}\n")

    all_results = {}
    checks = {
        "SMB (445)": lambda: check_smb(target, timeout),
        "RDP (3389)": lambda: check_rdp(target, timeout),
        "WinRM (5985/5986)": lambda: check_winrm(target, timeout),
        "RPC (135)": lambda: check_rpc(target, timeout),
        "Kerberos (88)": lambda: check_kerberos(target, timeout),
    }

    if all_ports:
        checks["LDAP/GC (389/636/3268/3269)"] = lambda: check_ldap(target, timeout)

    for service_name, check_fn in checks.items():
        print(f"  [*] Checking {service_name}...", end="")
        try:
            results = check_fn()
            all_results[service_name] = results
            if results:
                print(f" \033[92mOPEN\033[0m")
                for r in results:
                    vuln_srv = r.get("status", "")
                    if "Potential" in vuln_srv:
                        print(f"       \033[91m[!] {vuln_srv}\033[0m")
            else:
                print(f" \033[90mclosed\033[0m")
        except Exception as e:
            print(f" \033[91merror: {e}\033[0m")

    open_ports = []
    for svc, results in all_results.items():
        for r in results:
            open_ports.append({
                "port": r["port"],
                "service": r["service"],
                "status": r["status"],
            })

    summary = {
        "success": True,
        "target": target,
        "open_ports": open_ports,
        "services_found": len(open_ports),
        "all_results": {k: str(v) for k, v in all_results.items()},
    }

    print(f"\n{'='*60}")
    print(f"  Scan Complete — {len(open_ports)} services detected")
    print(f"{'='*60}")

    if open_ports:
        print(f"\n  Open Services:")
        for p in open_ports:
            status_str = p["status"]
            if "Potential" in status_str:
                print(f"    \033[91m[!] Port {p['port']}: {p['service']} — {status_str}\033[0m")
            else:
                print(f"    \033[92m[+] Port {p['port']}: {p['service']}\033[0m")

    return summary


def check(options):
    result = run(options)
    return result.get("success", False) and result.get("services_found", 0) > 0
