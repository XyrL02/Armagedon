"""
Armagedon SMB Enumeration Module — Comprehensive SMB share, user, and session enumeration.

Uses nxc (netexec), smbclient, rpcclient, and enum4linux-ng for real SMB enumeration.
Supports authenticated and unauthenticated connections.

Enumerates:
  - SMB shares (list, access level, contents)
  - Local users via SAMR/rpcclient
  - Active sessions
  - Shared files/directories
  - Password policy (via SAMR)
  - Domain/workgroup information
  - OS fingerprinting from SMB banner
"""
import subprocess
import shutil
import os
import re
import json
import tempfile
import logging

log = logging.getLogger("armagedon.modules.auxiliary.smb_enum")

CVE = "N/A"
DESCRIPTION = "SMB Enum — Comprehensive SMB enumeration (shares, users, sessions, policy)"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 445,
    "TIMEOUT": 10,
    "SMBUSER": "",
    "SMBPASS": "",
    "SMBHASH": "",
    "DOMAIN": "",
    "ENUM_SHARES": True,
    "ENUM_USERS": True,
    "ENUM_SESSIONS": True,
    "ENUM_POLICY": True,
    "ENUM_INFO": True,
    "SHARE_LIST": "",
    "SHARE_DEPTH": 1,
    "OUTPUT_DIR": "",
    "VERBOSE": False,
}

REQUIRED = {"RHOSTS": True}
DESCRIPTIONS = {
    "RHOSTS": "Target IP address",
    "RPORT": "SMB port (default 445)",
    "TIMEOUT": "Connection timeout in seconds",
    "SMBUSER": "SMB username (leave empty for null/guest session)",
    "SMBPASS": "SMB password",
    "SMBHASH": "NTLM hash for pass-the-hash (SMBUSER required)",
    "DOMAIN": "Windows domain (WORKGROUP if empty)",
    "ENUM_SHARES": "Enumerate SMB shares",
    "ENUM_USERS": "Enumerate local users via SAMR",
    "ENUM_SESSIONS": "Enumerate active SMB sessions",
    "ENUM_POLICY": "Enumerate password policy via SAMR",
    "ENUM_INFO": "Enumerate domain/workgroup info",
    "SHARE_LIST": "Comma-separated shares to tree-connect and list (overrides auto-detect)",
    "SHARE_DEPTH": "Depth for directory listing (1=immediate children)",
    "OUTPUT_DIR": "Directory for output files",
    "VERBOSE": "Show detailed output",
}

# Default shares to always check
DEFAULT_SHARES = [
    "ADMIN$", "C$", "D$", "IPC$", "PRINT$", "SYSVOL",
    "NETLOGON", "SHARED", "PUBLIC", "DATA", "BACKUP",
    "USERS", "DOCUMENTS", "SHARE", "Files", "Temp",
    "Software", "Public", "Users$", "IPC$",
]


def _find_tool(name):
    """Locate a CLI tool on the system."""
    alt_names = {
        "nxc": "nxc",
        "smbclient": "smbclient",
        "rpcclient": "rpcclient",
        "enum4linux-ng": "enum4linux-ng",
        "enum4linux": "enum4linux",
    }
    path = shutil.which(alt_names.get(name, name))
    return path


def _run_cmd(cmd, timeout=60, stdin_data=None):
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin_data,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 1
    except Exception as e:
        return "", str(e), 1


def _build_auth_args():
    """Build SMB authentication argument list."""
    args = []
    smbuser = OPTIONS.get("SMBUSER", "")
    smbpass = OPTIONS.get("SMBPASS", "")
    smbhash = OPTIONS.get("SMBHASH", "")
    domain = OPTIONS.get("DOMAIN", "")

    if smbuser:
        if domain:
            args.extend(["-u", f"{domain}\\{smbuser}"])
        else:
            args.extend(["-u", smbuser])
        if smbpass:
            args.extend(["-p", smbpass])
        elif smbhash:
            args.extend(["-H", smbhash])
        else:
            args.extend(["-p", ""])
    else:
        # Null session
        args.extend(["-u", "", "-p", ""])

    return args


def _build_nxc_args():
    """Build nxc-specific auth args."""
    args = []
    smbuser = OPTIONS.get("SMBUSER", "")
    smbpass = OPTIONS.get("SMBPASS", "")
    smbhash = OPTIONS.get("SMBHASH", "")
    domain = OPTIONS.get("DOMAIN", "")

    if smbuser:
        args.extend(["-u", smbuser])
        if smbpass:
            args.extend(["-p", smbpass])
        elif smbhash:
            args.extend(["-H", smbhash])
        else:
            args.extend(["-p", ""])
    if domain:
        args.extend(["-d", domain])

    return args


# ──────────────────────────────────────────────────────────────────────
# Enumeration functions
# ──────────────────────────────────────────────────────────────────────

def _enum_shares_nxc(target, port, timeout):
    """Enumerate shares using nxc smb."""
    nxc = _find_tool("nxc")
    if not nxc:
        return None, "nxc not found"

    cmd = [nxc, "smb", target, "-p", str(port), "--shares"]
    cmd.extend(_build_nxc_args())

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)
    if rc != 0 and "STATUS_ACCESS_DENIED" in stderr:
        return None, "Access denied (requires valid credentials)"

    shares = []
    # Parse nxc share listing
    # Format: Sharename      Type      Comment
    #         ---------       ----      -------
    #         IPC$            Disk      Remote IPC
    in_shares = False
    for line in stdout.splitlines():
        if "Sharename" in line and "Type" in line:
            in_shares = True
            continue
        if in_shares and "----" in line:
            continue
        if in_shares and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                shares.append({
                    "name": parts[0],
                    "type": parts[1] if len(parts) > 1 else "Unknown",
                    "comment": " ".join(parts[2:]) if len(parts) > 2 else "",
                })
        elif in_shares and not line.strip():
            break

    return shares, None


def _enum_shares_smbclient(target, port, timeout):
    """Enumerate shares using smbclient -L."""
    smbclient = _find_tool("smbclient")
    if not smbclient:
        return None, "smbclient not found"

    cmd = [smbclient, "-L", f"//{target}", "-p", str(port), "-N"]
    auth = _build_auth_args()
    # Replace -N with actual credentials if we have them
    if OPTIONS.get("SMBUSER"):
        cmd = [smbclient, "-L", f"//{target}", "-p", str(port)]
        cmd.extend(auth)

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    shares = []
    # Parse smbclient output
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Disk"):
            parts = line.split(None, 1)
            if len(parts) >= 2:
                name = parts[1].strip()
                shares.append({"name": name, "type": "Disk", "comment": ""})
        elif line.startswith("IPC"):
            parts = line.split(None, 1)
            if len(parts) >= 2:
                name = parts[1].strip()
                shares.append({"name": name, "type": "IPC", "comment": ""})
        elif line.startswith("Printer"):
            parts = line.split(None, 1)
            if len(parts) >= 2:
                name = parts[1].strip()
                shares.append({"name": name, "type": "Printer", "comment": ""})

    return shares, None


def _tree_connect(target, port, share, timeout):
    """Tree-connect to a share and list contents using smbclient."""
    smbclient = _find_tool("smbclient")
    if not smbclient:
        return None, "smbclient not found"

    cmd = [smbclient, f"//{target}/{share}", "-p", str(port), "-c", "ls"]
    auth = _build_auth_args()
    if OPTIONS.get("SMBUSER"):
        cmd = [smbclient, f"//{target}/{share}", "-p", str(port)]
        cmd.extend(auth)
        cmd.extend(["-c", "ls"])
    else:
        cmd.extend(["-N", "-c", "ls"])

    depth = int(OPTIONS.get("SHARE_DEPTH", 1))
    if depth > 1:
        ls_cmd = "recurse on; ls"
        cmd[-1] = ls_cmd

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    if rc != 0:
        error_msg = stderr.strip() or stdout.strip()
        if "NT_STATUS_ACCESS_DENIED" in error_msg:
            return None, "Access denied"
        elif "NT_STATUS_BAD_NETWORK_NAME" in error_msg:
            return None, "Share not found"
        elif "NT_STATUS_LOGON_FAILURE" in error_msg:
            return None, "Logon failure"
        return None, error_msg[:200]

    files = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("getting") or "recursing" in line.lower():
            continue
        # smbclient ls format:  .                D        0  Mon Jan  1 00:00:00 2024
        # or:                   file.txt         A      123  Mon Jan  1 00:00:00 2024
        match = re.match(r'^(.+?)\s+([DADR ]+)\s+(\d+)\s+(.+)$', line)
        if match:
            name = match.group(1).strip()
            ftype = "DIR" if "D" in match.group(2) else "FILE"
            size = match.group(3)
            date = match.group(4).strip()
            files.append({"name": name, "type": ftype, "size": size, "date": date})

    return files, None


def _enum_users_rpcclient(target, port, timeout):
    """Enumerate local users via rpcclient enumdomusers."""
    rpcclient = _find_tool("rpcclient")
    if not rpcclient:
        return None, "rpcclient not found"

    cmd = [rpcclient, f"//{target}", "-p", str(port)]
    auth = _build_auth_args()
    cmd.extend(auth)

    # Run enumdomusers
    stdin_data = "enumdomusers\nquit\n"
    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout, stdin_data=stdin_data)

    users = []
    for line in stdout.splitlines():
        # Format: user:[rid]
        match = re.search(r'(\w+):\[\d+\]', line)
        if match:
            users.append(match.group(1))

    return users, None


def _enum_users_nxc(target, port, timeout):
    """Enumerate users using nxc smb (samr module)."""
    nxc = _find_tool("nxc")
    if not nxc:
        return None, "nxc not found"

    cmd = [nxc, "smb", target, "-p", str(port), "-M", "samr"]
    cmd.extend(_build_nxc_args())

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    users = []
    for line in stdout.splitlines():
        # nxc samr output: "Username: Administrator" or "Username: guest"
        match = re.search(r'Username:\s*(\S+)', line)
        if match:
            users.append(match.group(1))
        # Alternative format: "User: Administrator (RID: 500)"
        match2 = re.search(r'User:\s*(\S+)', line)
        if match2 and match2.group(1) not in users:
            users.append(match2.group(1))

    return users, None


def _enum_sessions_nxc(target, port, timeout):
    """Enumerate active SMB sessions using nxc."""
    nxc = _find_tool("nxc")
    if not nxc:
        return None, "nxc not found"

    cmd = [nxc, "smb", target, "-p", str(port), "-M", "sessions"]
    cmd.extend(_build_nxc_args())

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    sessions = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("SMB") or "---" in line:
            continue
        # Parse session output
        parts = re.split(r'\s{2,}', line)
        if len(parts) >= 2:
            sessions.append({
                "client": parts[0],
                "user": parts[1] if len(parts) > 1 else "",
                "share": parts[2] if len(parts) > 2 else "",
            })

    return sessions, None


def _enum_sessions_smbclient(target, port, timeout):
    """Enumerate sessions using smbclient -L with session info."""
    smbclient = _find_tool("smbclient")
    if not smbclient:
        return None, "smbclient not found"

    cmd = [smbclient, "-L", f"//{target}", "-p", str(port)]
    auth = _build_auth_args()
    if OPTIONS.get("SMBUSER"):
        cmd.extend(auth)
    else:
        cmd.extend(["-N"])

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    sessions = []
    in_sessions = False
    for line in stdout.splitlines():
        if "Session" in line and "Machine" in line:
            in_sessions = True
            continue
        if in_sessions and "----" in line:
            continue
        if in_sessions and line.strip():
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 2:
                sessions.append({
                    "client": parts[0],
                    "user": parts[1] if len(parts) > 1 else "",
                })
        elif in_sessions and not line.strip():
            break

    return sessions, None


def _enum_policy_rpcclient(target, port, timeout):
    """Enumerate password policy via rpcclient."""
    rpcclient = _find_tool("rpcclient")
    if not rpcclient:
        return None, "rpcclient not found"

    cmd = [rpcclient, f"//{target}", "-p", str(port)]
    auth = _build_auth_args()
    cmd.extend(auth)

    stdin_data = "getdompwinfo\nquit\n"
    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout, stdin_data=stdin_data)

    policy = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "min_password_length" in line.lower() or "minPwdLength" in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                policy["min_password_length"] = int(match.group(1))
        if "password_history" in line.lower() or "pwdHistoryLength" in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                policy["password_history_length"] = int(match.group(1))
        if "password_properties" in line.lower() or "pwdProperties" in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                policy["password_properties"] = int(match.group(1))
        if "account_lockout" in line.lower() or "lockout" in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                policy["lockout_threshold"] = int(match.group(1))

    return policy, None


def _enum_info_nxc(target, port, timeout):
    """Enumerate domain/workgroup info using nxc."""
    nxc = _find_tool("nxc")
    if not nxc:
        return None, "nxc not found"

    cmd = [nxc, "smb", target, "-p", str(port)]
    cmd.extend(_build_nxc_args())

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout)

    info = {}
    # nxc prints OS info in the banner
    for line in stdout.splitlines():
        if "SMB" in line and ("Windows" in line or "Server" in line):
            info["os_info"] = line.strip()
        if "Domain:" in line or "domain:" in line:
            match = re.search(r'[Dd]omain:\s*(\S+)', line)
            if match:
                info["domain"] = match.group(1)
        if "Workgroup:" in line or "workgroup:" in line:
            match = re.search(r'[Ww]orkgroup:\s*(\S+)', line)
            if match:
                info["workgroup"] = match.group(1)
        if "FQDN:" in line:
            match = re.search(r'FQDN:\s*(\S+)', line)
            if match:
                info["fqdn"] = match.group(1)
        if "OS:" in line or "os:" in line:
            match = re.search(r'OS:\s*(.+)', line)
            if match:
                info["os"] = match.group(1).strip()

    # Also parse from smbclient if available
    smbclient = _find_tool("smbclient")
    if smbclient:
        cmd = [smbclient, "-L", f"//{target}", "-p", str(port)]
        auth = _build_auth_args()
        if OPTIONS.get("SMBUSER"):
            cmd.extend(auth)
        else:
            cmd.extend(["-N"])
        stdout2, _, rc2 = _run_cmd(cmd, timeout=timeout)
        if rc2 == 0:
            for line in stdout2.splitlines():
                if "Domain" in line and "=" in line:
                    match = re.search(r'Domain\s*[=:]\s*(\S+)', line)
                    if match and "domain" not in info:
                        info["domain"] = match.group(1)
                if "OS" in line and "=" in line:
                    match = re.search(r'OS\s*[=:]\s*(.+)', line)
                    if match and "os" not in info:
                        info["os"] = match.group(1).strip()

    return info, None


def _enum_shares_enum4linux(target, port, timeout):
    """Enumerate using enum4linux-ng (if available)."""
    enum4linux = _find_tool("enum4linux-ng") or _find_tool("enum4linux")
    if not enum4linux:
        return None, "enum4linux not found"

    cmd = [enum4linux, "-A", "-p", str(port), target]
    if OPTIONS.get("SMBUSER"):
        cmd.extend(["-u", OPTIONS["SMBUSER"]])
    if OPTIONS.get("SMBPASS"):
        cmd.extend(["-p_pass", OPTIONS["SMBPASS"]])

    stdout, stderr, rc = _run_cmd(cmd, timeout=timeout * 2)

    result = {"raw": stdout[:5000]}  # Truncate for storage
    return result, None


# ──────────────────────────────────────────────────────────────────────
# Main interface
# ──────────────────────────────────────────────────────────────────────

def check(options=None, target=None, **kwargs):
    """Verify prerequisites for SMB enumeration."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    if not opts.get("RHOSTS"):
        return False, "RHOSTS required."

    # Check for at least one SMB tool
    tools_found = []
    for tool in ["nxc", "smbclient", "rpcclient"]:
        if _find_tool(tool):
            tools_found.append(tool)

    if not tools_found:
        return False, "No SMB tools found. Install: nxc, smbclient, or rpcclient"

    return True, f"Target: {opts['RHOSTS']}:{opts.get('RPORT', 445)}, Tools: {', '.join(tools_found)}"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute SMB enumeration.

    Args:
        options: Module options dict.
        target: Target IP (overrides RHOSTS).
        mode: CHECK validates prerequisites, EXPLOIT runs enumeration.
    """
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    # Update global OPTIONS with current opts for helper functions
    OPTIONS.update(opts)

    host = opts.get("RHOSTS", "")
    port = int(opts.get("RPORT", 445))
    timeout = int(opts.get("TIMEOUT", 10))
    enum_shares = opts.get("ENUM_SHARES", True)
    enum_users = opts.get("ENUM_USERS", True)
    enum_sessions = opts.get("ENUM_SESSIONS", True)
    enum_policy = opts.get("ENUM_POLICY", True)
    enum_info = opts.get("ENUM_INFO", True)
    verbose = opts.get("VERBOSE", False)

    log.info(f"SMB enum target={host}:{port} mode={mode}")

    print(f"\n{'='*60}")
    print(f"  Armagedon — SMB Enumeration")
    print(f"  Target: {host}:{port}")
    auth_desc = "null session"
    if opts.get("SMBUSER"):
        auth_desc = f"{opts.get('DOMAIN', '')}\\{opts['SMBUSER']}"
    print(f"  Auth: {auth_desc}")
    print(f"{'='*60}")

    # CHECK mode
    if mode.upper() == "CHECK":
        ok, msg = check(opts, target)
        if ok:
            print(f"[+] Ready for enumeration.")
            return {"success": True, "message": msg}
        else:
            print(f"[-] Check failed: {msg}")
            return {"success": False, "error": msg}

    # EXPLOIT mode
    results = {
        "target": host,
        "port": port,
        "shares": [],
        "users": [],
        "sessions": [],
        "policy": {},
        "info": {},
    }

    # 1. Domain/Workgroup Info
    if enum_info:
        print(f"\n[*] Enumerating domain/workgroup info...")
        info, err = _enum_info_nxc(host, port, timeout)
        if info:
            results["info"] = info
            for k, v in info.items():
                print(f"  {k}: {v}")
        elif err:
            print(f"  [-] {err}")

    # 2. Share Enumeration
    if enum_shares:
        print(f"\n[*] Enumerating SMB shares...")

        # Try nxc first
        shares, err = _enum_shares_nxc(host, port, timeout)
        if shares is None:
            # Fallback to smbclient
            shares, err = _enum_shares_smbclient(host, port, timeout)

        if shares:
            results["shares"] = shares
            print(f"  Found {len(shares)} shares:")
            for s in shares:
                access = _test_share_access(host, port, s["name"])
                access_str = f" [\033[92m{access}\033[0m]" if access == "READ" else f" [\033[91m{access}\033[0m]" if access in ("DENIED", "NO ACCESS") else ""
                comment = f" ({s['comment']})" if s.get("comment") else ""
                print(f"    {s['name']:20s} {s['type']:10s}{comment}{access_str}")
        else:
            print(f"  [-] No shares found or access denied: {err or 'unknown error'}")

    # 3. User Enumeration
    if enum_users:
        print(f"\n[*] Enumerating local users...")

        # Try rpcclient first (more reliable for user enum)
        users, err = _enum_users_rpcclient(host, port, timeout)
        if not users:
            # Fallback to nxc
            users, err = _enum_users_nxc(host, port, timeout)

        if users:
            results["users"] = users
            print(f"  Found {len(users)} users:")
            for u in users:
                print(f"    - {u}")
        else:
            print(f"  [-] No users found or access denied: {err or 'unknown error'}")

    # 4. Session Enumeration
    if enum_sessions:
        print(f"\n[*] Enumerating active sessions...")

        sessions, err = _enum_sessions_nxc(host, port, timeout)
        if not sessions:
            sessions, err = _enum_sessions_smbclient(host, port, timeout)

        if sessions:
            results["sessions"] = sessions
            print(f"  Found {len(sessions)} active session(s):")
            for s in sessions:
                print(f"    Client: {s.get('client', 'N/A')}  User: {s.get('user', 'N/A')}")
        else:
            print(f"  [-] No sessions found or access denied: {err or 'unknown error'}")

    # 5. Password Policy
    if enum_policy:
        print(f"\n[*] Enumerating password policy...")

        policy, err = _enum_policy_rpcclient(host, port, timeout)
        if policy:
            results["policy"] = policy
            for k, v in policy.items():
                print(f"    {k}: {v}")
        else:
            print(f"  [-] Could not retrieve policy: {err or 'unknown error'}")

    # 6. List contents of interesting shares
    if opts.get("SHARE_LIST"):
        shares_to_list = [s.strip() for s in opts["SHARE_LIST"].split(",")]
    elif results["shares"]:
        # List contents of non-IPC/ADMIN shares
        shares_to_list = [s["name"] for s in results["shares"]
                         if s["name"] not in ("IPC$", "ADMIN$", "PRINT$")]
    else:
        shares_to_list = []

    if shares_to_list:
        print(f"\n[*] Tree-connecting to {len(shares_to_list)} share(s)...")
        share_contents = {}
        for share in shares_to_list[:10]:  # Limit to 10 shares
            print(f"  Listing {share}...")
            files, err = _tree_connect(host, port, share, timeout)
            if files:
                share_contents[share] = files
                # Show immediate children
                for f in files[:20]:  # Limit display
                    icon = "\033[94m[D]\033[0m" if f["type"] == "DIR" else "   "
                    print(f"    {icon} {f['name']}")
                if len(files) > 20:
                    print(f"    ... and {len(files) - 20} more items")
            elif err:
                print(f"    [-] {err}")
        results["share_contents"] = share_contents

    # 7. enum4linux-ng (comprehensive, if available)
    if verbose:
        print(f"\n[*] Running enum4linux-ng (if available)...")
        e4l, err = _enum_shares_enum4linux(host, port, timeout)
        if e4l:
            results["enum4linux"] = e4l
            print(f"  enum4linux-ng completed")
        elif err:
            print(f"  [-] {err}")

    # Export results
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        output_dir = os.path.join(tempfile.gettempdir(), "armagedon_smb")
    os.makedirs(output_dir, exist_ok=True)

    export_file = os.path.join(output_dir, "smb_enum_results.json")
    try:
        with open(export_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Results exported to {export_file}")
    except Exception as e:
        print(f"    [!] Export error: {e}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  SMB ENUM SUMMARY — {host}:{port}")
    print(f"{'='*60}")
    print(f"  Shares:     {len(results['shares'])}")
    print(f"  Users:      {len(results['users'])}")
    print(f"  Sessions:   {len(results['sessions'])}")
    print(f"  Policy:     {'Yes' if results['policy'] else 'No'}")
    print(f"  Info:       {results['info'].get('domain', results['info'].get('workgroup', 'N/A'))}")
    print(f"{'='*60}\n")

    return {
        "success": True,
        "results": results,
        "export_file": export_file,
        "share_count": len(results["shares"]),
        "user_count": len(results["users"]),
        "session_count": len(results["sessions"]),
    }


def _test_share_access(target, port, share):
    """Test if we can connect to a share. Returns access level."""
    smbclient = _find_tool("smbclient")
    if not smbclient:
        return "UNKNOWN"

    cmd = [smbclient, f"//{target}/{share}", "-p", str(port), "-c", "ls"]
    auth = _build_auth_args()
    if OPTIONS.get("SMBUSER"):
        cmd = [smbclient, f"//{target}/{share}", "-p", str(port)]
        cmd.extend(auth)
        cmd.extend(["-c", "ls"])
    else:
        cmd.extend(["-N", "-c", "ls"])

    stdout, stderr, rc = _run_cmd(cmd, timeout=10)

    if rc == 0 and stdout.strip():
        return "READ"
    elif "ACCESS_DENIED" in (stderr + stdout).upper():
        return "DENIED"
    elif "LOGON_FAILURE" in (stderr + stdout).upper():
        return "NO ACCESS"
    else:
        return "NO ACCESS"
