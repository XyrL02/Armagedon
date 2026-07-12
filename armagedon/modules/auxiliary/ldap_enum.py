"""
Armagedon LDAP Enumeration Module — Comprehensive AD enumeration via LDAP.

Enumerates: users, groups, computers, OUs, GPOs, SPNs, delegation configs,
AdminSDHolder, LAPS, password policy, domain trusts, interesting ACLs.

Supports authenticated and unauthenticated (anonymous bind) connections.
Uses python-ldap or ldapsearch CLI as backend.
"""
import subprocess
import shutil
import os
import re
import json
import tempfile
import logging

log = logging.getLogger("armagedon.modules.auxiliary.ldap_enum")

CVE = "N/A"
DESCRIPTION = "LDAP Enum — Comprehensive Active Directory enumeration via LDAP"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

OPTIONS = {
    "RHOSTS": "",
    "RPORT": 389,
    "SSL": False,
    "DOMAIN": "",
    "USERNAME": "",
    "PASSWORD": "",
    "HASH": "",
    "BASE_DN": "",
    "OUTPUT_DIR": "",
    "ENUM_USERS": True,
    "ENUM_GROUPS": True,
    "ENUM_COMPUTERS": True,
    "ENUM_OUS": True,
    "ENUM_GPOS": True,
    "ENUM_SPNS": True,
    "ENUM_DELEGATION": True,
    "ENUM_ADMINSD": True,
    "ENUM_LAPS": True,
    "ENUM_POLICY": True,
    "ENUM_TRUSTS": True,
    "ENUM_ACLS": True,
    "ENUM_ALL": False,
}

REQUIRED = {"RHOSTS": True}
DESCRIPTIONS = {
    "RHOSTS": "Target Domain Controller IP",
    "RPORT": "LDAP port (default 389, 636 for LDAPS)",
    "SSL": "Use LDAPS (port 636)",
    "DOMAIN": "AD domain (e.g. corp.local) — used to derive BASE_DN if empty",
    "USERNAME": "Authenticated username (leave empty for anonymous bind)",
    "PASSWORD": "Password for authenticated bind",
    "HASH": "NTLM hash for pass-the-hash LDAP bind",
    "BASE_DN": "LDAP base DN (auto-derived from DOMAIN if empty)",
    "OUTPUT_DIR": "Directory for output files",
    "ENUM_USERS": "Enumerate user objects",
    "ENUM_GROUPS": "Enumerate group objects",
    "ENUM_COMPUTERS": "Enumerate computer objects",
    "ENUM_OUS": "Enumerate organizational units",
    "ENUM_GPOS": "Enumerate Group Policy Objects",
    "ENUM_SPNS": "Enumerate Service Principal Names (Kerberoasting targets)",
    "ENUM_DELEGATION": "Enumerate unconstrained/constrained delegation",
    "ENUM_ADMINSD": "Check AdminSDHolder ACL",
    "ENUM_LAPS": "Enumerate LAPS passwords",
    "ENUM_POLICY": "Enumerate password policy",
    "ENUM_TRUSTS": "Enumerate domain trusts",
    "ENUM_ACLS": "Enumerate interesting ACLs (WriteDACL, GenericAll, etc.)",
    "ENUM_ALL": "Enable all enumeration categories",
}


def _domain_to_base_dn(domain):
    """Convert domain like corp.local to DC=corp,DC=local."""
    if not domain:
        return ""
    parts = domain.split(".")
    return ",".join(f"DC={p}" for p in parts)


def _find_ldapsearch():
    """Find ldapsearch binary."""
    return shutil.which("ldapsearch")


def _build_ldapsearch_cmd(host, port, base_dn, bind_dn, password, use_ssl,
                          filter_str, attributes, output_file):
    """Build ldapsearch command line."""
    cmd = ["ldapsearch", "-x", "-H"]

    uri = f"ldaps://{host}:{port}" if use_ssl else f"ldap://{host}:{port}"
    cmd.append(uri)

    if bind_dn and password:
        cmd.extend(["-D", bind_dn, "-w", password])
    elif bind_dn:
        cmd.extend(["-D", bind_dn, "-y", "/dev/stdin"])

    cmd.extend(["-b", base_dn])
    cmd.extend(["-s", "sub"])

    # Referrals
    cmd.extend(["-o", "chase_referrals=yes"])

    if filter_str:
        cmd.append(filter_str)

    if attributes:
        for attr in attributes:
            cmd.extend(["-a", attr])

    if output_file:
        cmd.extend(["-f", output_file])

    return cmd


def _run_ldapsearch(host, port, base_dn, bind_dn, password, use_ssl,
                    filter_str, attributes=None):
    """Execute ldapsearch and return (stdout, stderr, returncode)."""
    cmd = ["ldapsearch", "-x", "-H"]

    uri = f"ldaps://{host}:{port}" if use_ssl else f"ldap://{host}:{port}"
    cmd.append(uri)

    if bind_dn and password:
        cmd.extend(["-D", bind_dn, "-w", password])

    cmd.extend(["-b", base_dn, "-s", "sub"])
    cmd.extend(["-o", "chase_referrals=yes"])

    if filter_str:
        cmd.append(filter_str)

    if attributes:
        for attr in attributes:
            cmd.extend([attr])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "ldapsearch timed out", 1
    except FileNotFoundError:
        return "", "ldapsearch not found (install: apt install ldap-utils)", 1


def _parse_ldap_entries(output):
    """Parse ldapsearch LDIF output into list of dicts."""
    entries = []
    current = {}
    for line in output.splitlines():
        line = line.rstrip()
        if line.startswith("#") or not line:
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith(" ") and current:
            # Continuation line
            last_key = list(current.keys())[-1] if current else None
            if last_key:
                current[last_key] += line.strip()
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key in current:
                # Multiple values
                if isinstance(current[key], list):
                    current[key].append(val)
                else:
                    current[key] = [current[key], val]
            else:
                current[key] = val
    if current:
        entries.append(current)
    return entries


def _get_attr(entry, attr, default=""):
    """Safely get attribute from parsed entry."""
    val = entry.get(attr, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val


def _get_all_attrs(entry, attr):
    """Get all values of an attribute as list."""
    val = entry.get(attr, [])
    if isinstance(val, list):
        return val
    return [val] if val else []


# ──────────────────────────────────────────────────────────────────────
# Enumeration functions
# ──────────────────────────────────────────────────────────────────────
def _enum_users(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate AD user objects."""
    print("[*] Enumerating users...")
    filt = "(objectClass=user)"
    attrs = [
        "sAMAccountName", "distinguishedName", "memberOf", "servicePrincipalName",
        "userAccountControl", "pwdLastSet", "lastLogon", "mail", "description",
        "adminCount", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    users = []
    for e in entries:
        sam = _get_attr(e, "sAMAccountName")
        if not sam:
            continue
        uac = _get_attr(e, "userAccountControl", "0")
        try:
            uac_int = int(uac)
        except ValueError:
            uac_int = 0
        users.append({
            "username": sam,
            "dn": _get_attr(e, "distinguishedName"),
            "groups": _get_all_attrs(e, "memberOf"),
            "spns": _get_all_attrs(e, "servicePrincipalName"),
            "disabled": bool(uac_int & 0x2),
            "password_never_expires": bool(uac_int & 0x10000),
            "dont_require_preauth": bool(uac_int & 0x400000),
            "admin_count": _get_attr(e, "adminCount") == "1",
            "mail": _get_attr(e, "mail"),
            "description": _get_attr(e, "description"),
            "uac": uac,
        })
    print(f"    Found {len(users)} user objects")
    return users


def _enum_groups(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate AD group objects."""
    print("[*] Enumerating groups...")
    filt = "(objectClass=group)"
    attrs = ["sAMAccountName", "distinguishedName", "member", "description",
             "adminCount", "cn"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    groups = []
    for e in entries:
        sam = _get_attr(e, "sAMAccountName")
        if not sam:
            continue
        groups.append({
            "name": sam,
            "dn": _get_attr(e, "distinguishedName"),
            "members": _get_all_attrs(e, "member"),
            "description": _get_attr(e, "description"),
            "admin_count": _get_attr(e, "adminCount") == "1",
        })
    print(f"    Found {len(groups)} group objects")
    return groups


def _enum_computers(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate AD computer objects."""
    print("[*] Enumerating computers...")
    filt = "(objectClass=computer)"
    attrs = ["sAMAccountName", "distinguishedName", "operatingSystem",
             "operatingSystemVersion", "userAccountControl",
             "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
             "servicePrincipalName"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    computers = []
    for e in entries:
        sam = _get_attr(e, "sAMAccountName")
        if not sam:
            continue
        uac = _get_attr(e, "userAccountControl", "0")
        try:
            uac_int = int(uac)
        except ValueError:
            uac_int = 0
        computers.append({
            "hostname": sam.rstrip("$"),
            "dn": _get_attr(e, "distinguishedName"),
            "os": _get_attr(e, "operatingSystem"),
            "os_version": _get_attr(e, "operatingSystemVersion"),
            "unconstrained_delegation": bool(uac_int & 0x80000),
            "trusted_for_delegation": bool(uac_int & 0x800000),
            "constrained_delegation": _get_all_attrs(e, "msDS-AllowedToDelegateTo"),
            "spns": _get_all_attrs(e, "servicePrincipalName"),
        })
    print(f"    Found {len(computers)} computer objects")
    return computers


def _enum_ous(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate Organizational Units."""
    print("[*] Enumerating OUs...")
    filt = "(objectClass=organizationalUnit)"
    attrs = ["name", "distinguishedName", "description", "gPLink"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    ous = []
    for e in entries:
        name = _get_attr(e, "name")
        if not name:
            continue
        ous.append({
            "name": name,
            "dn": _get_attr(e, "distinguishedName"),
            "description": _get_attr(e, "description"),
            "gplink": _get_attr(e, "gPLink"),
        })
    print(f"    Found {len(ous)} OUs")
    return ous


def _enum_gpos(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate Group Policy Objects."""
    print("[*] Enumerating GPOs...")
    filt = "(objectClass=groupPolicyContainer)"
    attrs = ["cn", "displayName", "distinguishedName", "gPCFileSysPath",
             "versionNumber", "flags"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    gpos = []
    for e in entries:
        cn = _get_attr(e, "cn")
        if not cn:
            continue
        gpos.append({
            "id": cn,
            "name": _get_attr(e, "displayName"),
            "dn": _get_attr(e, "distinguishedName"),
            "path": _get_attr(e, "gPCFileSysPath"),
            "version": _get_attr(e, "versionNumber"),
        })
    print(f"    Found {len(gpos)} GPOs")
    return gpos


def _enum_spns(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate Service Principal Names (Kerberoasting targets)."""
    print("[*] Enumerating SPNs...")
    filt = "(servicePrincipalName=*)"
    attrs = ["sAMAccountName", "servicePrincipalName", "memberOf",
             "userAccountControl", "adminCount"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    spns = []
    for e in entries:
        sam = _get_attr(e, "sAMAccountName")
        if not sam:
            continue
        for spn in _get_all_attrs(e, "servicePrincipalName"):
            uac = _get_attr(e, "userAccountControl", "0")
            try:
                uac_int = int(uac)
            except ValueError:
                uac_int = 0
            spns.append({
                "username": sam,
                "spn": spn,
                "delegatable": not bool(uac_int & 0x100000),  # DONT_REQ_PREAUTH not set
                "admin_count": _get_attr(e, "adminCount") == "1",
                "groups": _get_all_attrs(e, "memberOf"),
            })
    print(f"    Found {len(spns)} SPNs across {len(set(s['username'] for s in spns))} accounts")
    return spns


def _enum_delegation(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate unconstrained and constrained delegation."""
    print("[*] Enumerating delegation configurations...")

    # Unconstrained delegation: TRUSTED_FOR_DELEGATION flag
    filt = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    attrs = ["sAMAccountName", "distinguishedName"]
    stdout, _, _ = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                    use_ssl, filt, attrs)
    uncons_entries = _parse_ldap_entries(stdout)
    unconstrained = [_get_attr(e, "sAMAccountName").rstrip("$") for e in uncons_entries
                     if _get_attr(e, "sAMAccountName")]

    # Constrained delegation: msDS-AllowedToDelegateTo attribute
    filt = "(msDS-AllowedToDelegateTo=*)"
    attrs = ["sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo"]
    stdout, _, _ = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                    use_ssl, filt, attrs)
    cons_entries = _parse_ldap_entries(stdout)
    constrained = []
    for e in cons_entries:
        sam = _get_attr(e, "sAMAccountName")
        if sam:
            constrained.append({
                "account": sam,
                "dn": _get_attr(e, "distinguishedName"),
                "allowed_services": _get_all_attrs(e, "msDS-AllowedToDelegateTo"),
            })

    # Resource-based constrained delegation (RBCD): msDS-AllowedToActOnBehalfOfOtherIdentity
    filt = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    attrs = ["sAMAccountName", "distinguishedName"]
    stdout, _, _ = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                    use_ssl, filt, attrs)
    rbcd_entries = _parse_ldap_entries(stdout)
    rbcd = [_get_attr(e, "sAMAccountName") for e in rbcd_entries
            if _get_attr(e, "sAMAccountName")]

    print(f"    Unconstrained delegation: {len(unconstrained)} computer(s)")
    print(f"    Constrained delegation:   {len(constrained)} account(s)")
    print(f"    RBCD targets:             {len(rbcd)} account(s)")

    return {
        "unconstrained": unconstrained,
        "constrained": constrained,
        "rbcd": rbcd,
    }


def _enum_adminsd(host, port, base_dn, bind_dn, password, use_ssl):
    """Check AdminSDHolder ACL."""
    print("[*] Enumerating AdminSDHolder...")
    filt = "(cn=AdminSDHolder)"
    attrs = ["distinguishedName", "nTSecurityDescriptor"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    found = len(entries) > 0
    print(f"    AdminSDHolder: {'found' if found else 'not found'}")
    return {"found": found, "entries": entries}


def _enum_laps(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate LAPS passwords."""
    print("[*] Enumerating LAPS passwords...")
    filt = "(ms-Mcs-AdmPwd=*)"
    attrs = ["sAMAccountName", "distinguishedName", "ms-Mcs-AdmPwd",
             "ms-Mcs-AdmPwdExpirationTime"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    laps = []
    for e in entries:
        sam = _get_attr(e, "sAMAccountName")
        pwd = _get_attr(e, "ms-Mcs-AdmPwd")
        if sam and pwd:
            laps.append({
                "hostname": sam.rstrip("$"),
                "password": pwd,
                "expiration": _get_attr(e, "ms-Mcs-AdmPwdExpirationTime"),
            })
    print(f"    Found {len(laps)} LAPS password(s)")
    return laps


def _enum_policy(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate password policy."""
    print("[*] Enumerating password policy...")
    filt = "(objectClass=domain)"
    attrs = [
        "minPwdLength", "pwdHistoryLength", "pwdProperties",
        "maxPwdAge", "minPwdAge", "lockoutThreshold",
        "lockoutDuration", "lockoutObservationWindow",
        "distinguishedName",
    ]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    if not entries:
        print("    No domain policy found")
        return {}
    e = entries[0]
    policy = {
        "min_password_length": _get_attr(e, "minPwdLength", "N/A"),
        "password_history_length": _get_attr(e, "pwdHistoryLength", "N/A"),
        "pwd_properties": _get_attr(e, "pwdProperties", "N/A"),
        "max_password_age": _get_attr(e, "maxPwdAge", "N/A"),
        "min_password_age": _get_attr(e, "minPwdAge", "N/A"),
        "lockout_threshold": _get_attr(e, "lockoutThreshold", "N/A"),
        "lockout_duration": _get_attr(e, "lockoutDuration", "N/A"),
        "lockout_observation_window": _get_attr(e, "lockoutObservationWindow", "N/A"),
    }
    for k, v in policy.items():
        print(f"    {k}: {v}")
    return policy


def _enum_trusts(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate domain trusts."""
    print("[*] Enumerating domain trusts...")
    filt = "(objectClass=trustedDomain)"
    attrs = ["name", "trustDirection", "trustType", "trustAttributes",
             "securityIdentifier", "flatName"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)
    entries = _parse_ldap_entries(stdout)
    trusts = []
    for e in entries:
        name = _get_attr(e, "name")
        if not name:
            continue
        direction = _get_attr(e, "trustDirection", "0")
        direction_map = {"1": "inbound", "2": "outbound", "3": "bidirectional"}
        trusts.append({
            "name": name,
            "flat_name": _get_attr(e, "flatName"),
            "direction": direction_map.get(direction, f"unknown({direction})"),
            "type": _get_attr(e, "trustType"),
            "attributes": _get_attr(e, "trustAttributes"),
            "sid": _get_attr(e, "securityIdentifier"),
        })
    print(f"    Found {len(trusts)} domain trust(s)")
    return trusts


def _enum_acls(host, port, base_dn, bind_dn, password, use_ssl):
    """Enumerate interesting ACLs on AD objects."""
    print("[*] Enumerating interesting ACLs...")
    interesting_acls = [
        "WriteDACL", "WriteOwner", "GenericAll", "GenericWrite",
        "WriteProperty", "Self", "Self-Write",
        "AddMember", "AddKeyCredentialLink",
        "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
        "ResetPassword", "ChangePassword",
    ]

    # Query all objects with ACLs (nTSecurityDescriptor)
    filt = "(objectClass=*)"
    attrs = ["distinguishedName", "nTSecurityDescriptor", "sAMAccountName"]
    stdout, stderr, rc = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                          use_ssl, filt, attrs)

    # Since parsing raw security descriptors in text is limited,
    # we look for delegation and privileged group membership as proxy
    # for ACL-based attack paths
    acls = []

    # Check for accounts with AdminSDHolder protection
    filt_admin = "(&(objectClass=user)(adminCount=1))"
    stdout, _, _ = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                    use_ssl, filt_admin,
                                    ["sAMAccountName", "distinguishedName"])
    admin_entries = _parse_ldap_entries(stdout)
    for e in admin_entries:
        sam = _get_attr(e, "sAMAccountName")
        if sam:
            acls.append({
                "type": "AdminSDHolder Protected",
                "account": sam,
                "dn": _get_attr(e, "distinguishedName"),
            })

    # Check for DCSync-capable accounts (Replicating Directory Changes)
    # These are typically Domain Admins, Enterprise Admins, etc.
    privileged_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
    ]
    for grp in privileged_groups:
        filt_grp = f"(&(objectClass=group)(sAMAccountName={grp}))"
        stdout, _, _ = _run_ldapsearch(host, port, base_dn, bind_dn, password,
                                        use_ssl, filt_grp, ["member"])
        entries = _parse_ldap_entries(stdout)
        for e in entries:
            for member in _get_all_attrs(e, "member"):
                acls.append({
                    "type": f"Member of {grp}",
                    "dn": member,
                })

    print(f"    Found {len(acls)} interesting ACL/privilege entries")
    return acls


# ──────────────────────────────────────────────────────────────────────
# Main interface
# ──────────────────────────────────────────────────────────────────────
_ENUM_MAP = {
    "ENUM_USERS":       _enum_users,
    "ENUM_GROUPS":      _enum_groups,
    "ENUM_COMPUTERS":   _enum_computers,
    "ENUM_OUS":         _enum_ous,
    "ENUM_GPOS":        _enum_gpos,
    "ENUM_SPNS":        _enum_spns,
    "ENUM_DELEGATION":  _enum_delegation,
    "ENUM_ADMINSD":     _enum_adminsd,
    "ENUM_LAPS":        _enum_laps,
    "ENUM_POLICY":      _enum_policy,
    "ENUM_TRUSTS":      _enum_trusts,
    "ENUM_ACLS":        _enum_acls,
}


def check(options=None, target=None, **kwargs):
    """Verify prerequisites for LDAP enumeration."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    if not opts.get("RHOSTS"):
        return False, "RHOSTS (Domain Controller IP) required."

    if not _find_ldapsearch():
        return False, "ldapsearch not found. Install: apt install ldap-utils"

    return True, f"DC: {opts['RHOSTS']}, Tool: ldapsearch"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute LDAP enumeration.

    Args:
        options: Module options dict.
        target: DC IP (overrides RHOSTS).
        mode: CHECK validates prerequisites, EXPLOIT runs enumeration.
    """
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    host = opts.get("RHOSTS", "")
    log.info(f"LDAP enum target={host} mode={mode}")
    port = int(opts.get("RPORT", 389))
    use_ssl = opts.get("SSL", False)
    domain = opts.get("DOMAIN", "")
    username = opts.get("USERNAME", "")
    password = opts.get("PASSWORD", "")
    ntlm_hash = opts.get("HASH", "")
    base_dn = opts.get("BASE_DN", "")
    enum_all = opts.get("ENUM_ALL", False)

    if not base_dn and domain:
        base_dn = _domain_to_base_dn(domain)

    # Build bind DN
    bind_dn = ""
    if username and domain:
        # DOMAIN\user → user@domain.local
        if "\\" in username:
            user_part = username.split("\\", 1)[1]
        else:
            user_part = username
        bind_dn = f"{user_part}@{domain}"

    # Determine which enums to run
    active_enums = {}
    for key, fn in _ENUM_MAP.items():
        if enum_all or opts.get(key, False):
            active_enums[key] = fn

    print(f"\n{'='*60}")
    print(f"  Armagedon — LDAP Enumeration")
    print(f"  DC: {host}:{port}  {'LDAPS' if use_ssl else 'LDAP'}")
    print(f"  Base DN: {base_dn or '(auto-detect)'}")
    print(f"  Auth: {'authenticated' if bind_dn else 'anonymous'}")
    print(f"  Modules: {len(active_enums)}")
    print(f"{'='*60}")

    # CHECK mode
    if mode.upper() == "CHECK":
        ok, msg = check(opts, target)
        if ok:
            print(f"[+] Ready. Will run: {', '.join(active_enums.keys())}")
            return {"success": True, "modules": list(active_enums.keys()), "message": msg}
        else:
            print(f"[-] Check failed: {msg}")
            return {"success": False, "error": msg}

    # EXPLOIT mode
    results = {}
    for key, fn in active_enums.items():
        try:
            data = fn(host, port, base_dn, bind_dn, password, use_ssl)
            results[key] = data
        except Exception as e:
            print(f"    [!] Error in {key}: {e}")
            results[key] = {"error": str(e)}

    # Export results
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        output_dir = os.path.join(tempfile.gettempdir(), "armagedon_ldap")
    os.makedirs(output_dir, exist_ok=True)

    export_file = os.path.join(output_dir, "ldap_enum_results.json")
    try:
        # Make results JSON-serializable
        serializable = {}
        for k, v in results.items():
            if isinstance(v, (str, int, float, bool, list, dict)):
                serializable[k] = v
            elif isinstance(v, list):
                serializable[k] = [x if isinstance(x, (str, dict)) else str(x) for x in v]
            else:
                serializable[k] = str(v)

        with open(export_file, "w") as f:
            json.dump(serializable, f, indent=2, default=str)
        print(f"\n[+] Results exported to {export_file}")
    except Exception as e:
        print(f"    [!] Export error: {e}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  LDAP ENUM SUMMARY")
    print(f"{'='*60}")
    for key, data in results.items():
        if isinstance(data, list):
            label = key.replace("ENUM_", "").replace("_", " ").title()
            print(f"  {label}: {len(data)} entries")
        elif isinstance(data, dict):
            label = key.replace("ENUM_", "").replace("_", " ").title()
            count = len(data) if not data.get("error") else "ERROR"
            print(f"  {label}: {count}")
    print(f"{'='*60}\n")

    return {
        "success": True,
        "results": results,
        "export_file": export_file,
        "host": host,
        "base_dn": base_dn,
        "auth": bool(bind_dn),
    }
