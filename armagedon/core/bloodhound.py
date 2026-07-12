"""
BloodHound Attack Path Analyzer

Parses BloodHound ingested JSON files (SharpHound collection output), builds a
relationship graph, and identifies privilege escalation attack paths from any
source user/group/computer to high-value targets (Domain Admins, Enterprise Admins,
Schema Admins, etc.).

Supports:
  - Full JSON collection (users.json, groups.json, computers.json, domains.json,
    gpos.json, ais.json, sessions.json)
  - Compact collection (single JSON with all object types)
  - Both SharpHound v4 and v5 formats

Attack path types detected:
  1. GROUP_MEMBERSHIP   — chain of MemberOf edges to DA
  2. ADMIN_ACCESS       — direct AdminTo on a computer that leads to DA
  3. SESSION_HIJACK     — HasSession on a computer + AdminTo on DA from there
  4. DELEGATION_ABUSE   — AllowedToDelegate (unconstrained/constrained delegation)
  5. RBCD_ABUSE         — GenericAll/WriteOwner/WriteDACL → RBCD on computer
  6. ACL_ABUSE          — GenericAll/WriteDACL/WriteOwner on user/group → DA
  7. PASSWORD_RESET     — ForceChangePassword on DA-privileged user
  8. ACL_CHAIN          — WriteDACL on a group → AddMember → DA
  9. SID_HISTORY        — HasSIDHistory abuse
 10. DCOM_ABUSE         — ExecuteDCOM on a computer
"""

import json
import os
import logging
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

log = logging.getLogger("armagedon.core.bloodhound")

# ── High-value target SIDs (well-known groups) ────────────────────────────────
# These SIDs represent groups that grant domain-level privileges.
HIGH_VALUE_SIDS = {
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-21-*-512": "DOMAIN ADMINS",
    "S-1-5-21-*-518": "SCHEMA ADMINS",
    "S-1-5-21-*-519": "ENTERPRISE ADMINS",
    "S-1-5-21-*-498": "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
    "S-1-5-21-*-522": "CLONEABLE DOMAIN CONTROLLERS",
}

HIGH_VALUE_NAMES = {
    "domain admins", "enterprise admins", "schema admins",
    "builtin\\administrators", "administrators",
    "account operators", "backup operators", "server operators",
    "dnsadmins", "exchange windows permissions",
    "privileged access management", " delegated administration",
}

# ── ACL rights that enable attack paths ───────────────────────────────────────
ACL_RIGHTS = {
    "GenericAll": "full_control",
    "GenericWrite": "write_all",
    "WriteOwner": "write_owner",
    "WriteDACL": "write_dacl",
    "OwnObject": "owns",
    "AddMember": "add_member",
    "AddSelf": "add_self",
    "ForceChangePassword": "reset_password",
    "AllExtendedRights": "all_extended",
    "AddKeyCredentialLink": "shadow_credentials",
    # BloodHound-specific edge types (also appear in Aces)
    "AdminTo": "admin_to",
    "HasSession": "has_session",
    "CanRDP": "can_rdp",
    "CanPSRemote": "can_ps_remote",
    "ExecuteDCOM": "execute_dcom",
    "AllowedToDelegate": "allowed_to_delegate",
    "AllowedToAct": "allowed_to_act",
    "HasSIDHistory": "has_sid_history",
}


@dataclass
class Node:
    """A single AD object (user, group, computer, GPO, OU, domain)."""
    object_id: str
    name: str
    object_type: str  # user, group, computer, domain, gpo, ou, container
    properties: dict = field(default_factory=dict)
    aces: list = field(default_factory=list)       # inbound ACLs
    members: list = field(default_factory=list)     # for groups
    sessions: list = field(default_factory=list)    # for computers
    spn_targets: list = field(default_factory=list) # kerberoastable
    is_high_value: bool = False
    is_owned: bool = False
    enabled: bool = True
    domain_sid: str = ""

    @property
    def display_name(self):
        return self.properties.get("name", self.name or self.object_id)


@dataclass
class Edge:
    """A relationship between two nodes."""
    source_id: str
    target_id: str
    edge_type: str     # MemberOf, AdminTo, HasSession, AllowedToDelegate, etc.
    properties: dict = field(default_factory=dict)
    weight: int = 1    # lower = easier to exploit

    @property
    def label(self):
        return self.edge_type


@dataclass
class AttackPath:
    """A discovered attack path from source to target."""
    source: str
    target: str
    edges: List[Edge]
    path_type: str
    description: str = ""
    severity: str = "high"  # critical, high, medium, low
    effort: str = "low"     # low, medium, high (attacker effort)
    auto_executable: bool = False
    auto_exec_module: str = ""
    auto_exec_options: dict = field(default_factory=dict)


class BloodHoundAnalyzer:
    """Parse BloodHound JSON and find attack paths."""

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.adj: Dict[str, List[Edge]] = defaultdict(list)  # outbound edges
        self.rev_adj: Dict[str, List[Edge]] = defaultdict(list)  # inbound edges
        self.high_value_nodes: Set[str] = set()
        self.domain_sids: Set[str] = set()
        self.computers: Dict[str, Node] = {}
        self.users: Dict[str, Node] = {}
        self.groups: Dict[str, Node] = {}
        self.attack_paths: List[AttackPath] = []
        self._loaded = False

    # ── Loading ────────────────────────────────────────────────────────────

    def load_from_directory(self, directory: str) -> bool:
        """Load BloodHound JSON files from a directory.

        Supports both individual files (users.json, groups.json, etc.) and
        the compact format (a single JSON with all object types).
        """
        directory = Path(directory)
        if not directory.is_dir():
            log.error("Not a directory: %s", directory)
            return False

        json_files = sorted(directory.glob("*.json"))
        if not json_files:
            log.error("No JSON files found in %s", directory)
            return False

        log.info("Found %d JSON files in %s", len(json_files), directory)

        loaded = 0
        for jf in json_files:
            try:
                data = json.loads(jf.read_text(errors="ignore"))
            except json.JSONDecodeError as e:
                log.warning("Skipping %s: %s", jf.name, e)
                continue

            # Handle compact format (single file with all types)
            if isinstance(data, list):
                loaded += self._parse_compact(data)
            elif isinstance(data, dict):
                # Check if it has "data" key (SharpHound v4/v5 format)
                if "data" in data:
                    loaded += self._parse_data_key(data["data"], jf.name)
                else:
                    # Try to guess type from filename
                    loaded += self._parse_data_key([data], jf.name)

        if loaded > 0:
            self._build_graph()
            self._mark_high_value()
            self._loaded = True
            log.info(
                "Loaded %d nodes, %d edges, %d high-value targets",
                len(self.nodes), len(self.edges), len(self.high_value_nodes),
            )
        return loaded > 0

    def load_from_file(self, filepath: str) -> bool:
        """Load a single BloodHound JSON file."""
        filepath = Path(filepath)
        if not filepath.is_file():
            log.error("Not a file: %s", filepath)
            return False

        try:
            data = json.loads(filepath.read_text(errors="ignore"))
        except json.JSONDecodeError as e:
            log.error("Invalid JSON: %s", e)
            return False

        if isinstance(data, list):
            loaded = self._parse_compact(data)
        elif isinstance(data, dict):
            if "data" in data:
                loaded = self._parse_data_key(data["data"], filepath.name)
            else:
                loaded = self._parse_data_key([data], filepath.name)
        else:
            return False

        if loaded > 0:
            self._build_graph()
            self._mark_high_value()
            self._loaded = True
        return loaded > 0

    def _parse_compact(self, data: list) -> int:
        """Parse compact BloodHound format (list of all objects)."""
        count = 0
        for obj in data:
            if self._add_node_from_obj(obj):
                count += 1
        return count

    def _parse_data_key(self, data_list: list, source_file: str) -> int:
        """Parse SharpHound v4/v5 format (data array with typed objects)."""
        count = 0
        for obj in data_list:
            if self._add_node_from_obj(obj):
                count += 1
        return count

    def _add_node_from_obj(self, obj: dict) -> bool:
        """Add a single object (user/group/computer/etc.) to the graph."""
        oid = obj.get("ObjectIdentifier") or obj.get("objectid") or obj.get("id", "")
        if not oid:
            return False

        props = obj.get("Properties", obj.get("properties", {}))
        obj_type = (
            props.get("objecttype", "").lower()
            or obj.get("ObjectType", "").lower()
            or self._guess_type(obj)
        )

        node = Node(
            object_id=oid,
            name=props.get("name", ""),
            object_type=obj_type,
            properties=props,
            enabled=props.get("enabled", True),
            is_owned=props.get("owned", False),
            domain_sid=props.get("domainsid", ""),
        )

        # Parse ACEs (inbound ACLs)
        aces = obj.get("Aces", obj.get("aces", []))
        for ace in aces:
            right = ace.get("RightName", ace.get("rightname", ""))
            principal_sid = ace.get("PrincipalSID", ace.get(" principalsid", ""))
            inherited = ace.get("IsInherited", ace.get("isinherited", False))
            if not inherited and principal_sid:
                node.aces.append({
                    "sid": principal_sid,
                    "right": right,
                    "type": ace.get("PrincipalType", ace.get("principaltype", "")),
                })

        # Parse Members (for groups)
        members = obj.get("Members", obj.get("members", []))
        for m in members:
            mid = m.get("MemberId", m.get("memberid", m.get("objectid", "")))
            if mid:
                node.members.append(mid)

        # Parse Sessions (for computers)
        sessions = obj.get("Sessions", obj.get("sessions", []))
        for s in sessions:
            uid = s.get("UserId", s.get("userid", s.get("objectid", "")))
            if uid:
                node.sessions.append(uid)

        # Check SPNs (kerberoastable)
        spns = props.get("hasspn", []) or props.get("serviceprincipalnames", [])
        if spns:
            node.spn_targets = spns if isinstance(spns, list) else [spns]

        self.nodes[oid] = node
        return True

    def _guess_type(self, obj: dict) -> str:
        """Guess object type from structure."""
        if "Members" in obj or "members" in obj:
            return "group"
        if "Sessions" in obj or "sessions" in obj:
            return "computer"
        if "Aces" in obj or "aces" in obj:
            return "user"
        return "unknown"

    # ── Graph building ─────────────────────────────────────────────────────

    def _build_graph(self):
        """Build adjacency lists from nodes and their embedded edges."""
        for oid, node in self.nodes.items():
            # Group membership: members → group (MemberOf edge)
            for member_id in node.members:
                edge = Edge(source_id=member_id, target_id=oid, edge_type="MemberOf")
                self.edges.append(edge)
                self.adj[member_id].append(edge)
                self.rev_adj[oid].append(edge)

            # Session edges: user → computer (HasSession edge)
            for user_id in node.sessions:
                edge = Edge(source_id=user_id, target_id=oid, edge_type="HasSession", weight=2)
                self.edges.append(edge)
                self.adj[user_id].append(edge)
                self.rev_adj[oid].append(edge)

                # Reverse: computer → user (session hijack — attacker on machine can steal token)
                rev = Edge(source_id=oid, target_id=user_id, edge_type="SessionHijack", weight=3)
                self.edges.append(rev)
                self.adj[oid].append(rev)
                self.rev_adj[user_id].append(rev)

            # ACL edges: ace principal → node (various rights)
            for ace in node.aces:
                sid = ace["sid"]
                right = ace["right"]
                if right in ACL_RIGHTS:
                    edge = Edge(
                        source_id=sid,
                        target_id=oid,
                        edge_type=right,
                        properties={"right": right},
                        weight=self._acl_weight(right),
                    )
                    self.edges.append(edge)
                    self.adj[sid].append(edge)
                    self.rev_adj[oid].append(edge)

                    # Add reverse edges for attack paths that require traversal
                    # HasSession: computer → user (session hijack)
                    if right == "HasSession":
                        rev = Edge(
                            source_id=oid, target_id=sid,
                            edge_type="SessionHijack",
                            properties={"right": "session_hijack"},
                            weight=3,
                        )
                        self.edges.append(rev)
                        self.adj[oid].append(rev)
                        self.rev_adj[sid].append(rev)

                    # AllowedToDelegate: target → source (delegation abuse)
                    if right == "AllowedToDelegate":
                        rev = Edge(
                            source_id=oid, target_id=sid,
                            edge_type="DelegationAbuse",
                            properties={"right": "delegation_abuse"},
                            weight=4,
                        )
                        self.edges.append(rev)
                        self.adj[oid].append(rev)
                        self.rev_adj[sid].append(rev)

    def _acl_weight(self, right: str) -> int:
        """Lower = easier to exploit."""
        weights = {
            "GenericAll": 1,
            "AllExtendedRights": 1,
            "ForceChangePassword": 2,
            "AddMember": 2,
            "AdminTo": 1,
            "HasSession": 2,
            "CanRDP": 2,
            "CanPSRemote": 2,
            "ExecuteDCOM": 3,
            "AllowedToDelegate": 3,
            "AllowedToAct": 3,
            "HasSIDHistory": 2,
            "AddSelf": 3,
            "WriteDACL": 2,
            "WriteOwner": 3,
            "GenericWrite": 4,
            "OwnObject": 2,
            "AddKeyCredentialLink": 3,
        }
        return weights.get(right, 5)

    def _mark_high_value(self):
        """Mark nodes that are high-value targets."""
        for oid, node in self.nodes.items():
            name_lower = node.name.lower()
            # Check by SID pattern
            for pattern in HIGH_VALUE_SIDS:
                if pattern.replace("*", "") in node.object_id:
                    node.is_high_value = True
                    self.high_value_nodes.add(oid)
                    break
            # Check by name
            if any(hv in name_lower for hv in HIGH_VALUE_NAMES):
                node.is_high_value = True
                self.high_value_nodes.add(oid)
            # Check admin count
            if node.properties.get("admincount", False):
                node.is_high_value = True
                self.high_value_nodes.add(oid)
            # Domain controllers
            if node.properties.get("isdc", False) or node.properties.get("isdomaincontroller", False):
                node.is_high_value = True
                self.high_value_nodes.add(oid)

    # ── Attack path analysis ───────────────────────────────────────────────

    def find_attack_paths(self, source_sid: str = None, max_depth: int = 8,
                          max_paths: int = 50) -> List[AttackPath]:
        """Find all attack paths from source to high-value targets.

        If source_sid is None, searches from all owned/enabled users.
        """
        if not self._loaded:
            log.error("No data loaded — call load_from_directory() first")
            return []

        # Determine starting points
        if source_sid:
            start_nodes = [source_sid] if source_sid in self.nodes else []
        else:
            start_nodes = [
                oid for oid, n in self.nodes.items()
                if n.object_type == "user" and n.enabled
            ]

        if not start_nodes:
            log.warning("No starting nodes found")
            return []

        log.info(
            "Searching attack paths from %d source(s) to %d high-value targets (max_depth=%d)",
            len(start_nodes), len(self.high_value_nodes), max_depth,
        )

        paths = []
        for start in start_nodes:
            found = self._bfs_paths(start, max_depth, max_paths - len(paths))
            paths.extend(found)
            if len(paths) >= max_paths:
                break

        # Deduplicate and rank
        paths = self._deduplicate_paths(paths)
        paths = self._rank_paths(paths)
        self.attack_paths = paths

        log.info("Found %d unique attack paths", len(paths))
        return paths

    def _bfs_paths(self, start_sid: str, max_depth: int,
                   max_paths: int) -> List[AttackPath]:
        """BFS from start_sid to find paths to high-value targets."""
        paths = []
        # Queue: (current_sid, path_edges, visited)
        queue = deque([(start_sid, [], set([start_sid]))])

        while queue and len(paths) < max_paths:
            current, path_edges, visited = queue.popleft()

            if len(path_edges) > max_depth:
                continue

            # Check if current node is high-value
            if current in self.high_value_nodes and path_edges:
                path_type = self._classify_path(path_edges)
                severity = self._path_severity(path_edges)
                effort = self._path_effort(path_edges)
                desc = self._describe_path(path_edges, start_sid, current)

                path = AttackPath(
                    source=start_sid,
                    target=current,
                    edges=list(path_edges),
                    path_type=path_type,
                    description=desc,
                    severity=severity,
                    effort=effort,
                    auto_executable=self._can_auto_exec(path_edges),
                    auto_exec_module=self._auto_exec_module(path_edges),
                    auto_exec_options=self._auto_exec_options(path_edges, start_sid),
                )
                paths.append(path)
                continue

            # Follow edges from current node
            for edge in self.adj.get(current, []):
                next_node = edge.target_id
                if next_node not in visited:
                    new_visited = visited | {next_node}
                    new_edges = path_edges + [edge]
                    queue.append((next_node, new_edges, new_visited))

        return paths

    def _classify_path(self, edges: List[Edge]) -> str:
        """Classify the attack path type based on edge types."""
        edge_types = [e.edge_type for e in edges]

        if "ForceChangePassword" in edge_types:
            return "PASSWORD_RESET"
        if "MemberOf" in edge_types and len(edge_types) == 1:
            return "GROUP_MEMBERSHIP"
        if "HasSession" in edge_types:
            return "SESSION_HIJACK"
        if "AllowedToDelegate" in edge_types:
            return "DELEGATION_ABUSE"
        if any(e in edge_types for e in ["GenericAll", "WriteOwner", "WriteDACL"]):
            if any(e in edge_types for e in ["MemberOf", "AddMember"]):
                return "ACL_CHAIN"
            if any("computer" in self.nodes.get(
                e.target_id, Node("", "", "")).object_type
                   for e in edges if e.edge_type in ["GenericAll", "WriteOwner", "WriteDACL"]):
                return "RBCD_ABUSE"
            return "ACL_ABUSE"
        if "AdminTo" in edge_types:
            return "ADMIN_ACCESS"
        if "ExecuteDCOM" in edge_types:
            return "DCOM_ABUSE"
        if "HasSIDHistory" in edge_types:
            return "SID_HISTORY"
        return "CHAIN"

    def _path_severity(self, edges: List[Edge]) -> str:
        """Rate path severity based on edge types and target."""
        critical_types = {"ForceChangePassword", "GenericAll", "AllExtendedRights"}
        high_types = {"WriteDACL", "WriteOwner", "AddMember", "AllowedToDelegate"}

        for e in edges:
            if e.edge_type in critical_types:
                return "critical"
        for e in edges:
            if e.edge_type in high_types:
                return "high"
        if len(edges) <= 2:
            return "high"
        return "medium"

    def _path_effort(self, edges: List[Edge]) -> str:
        """Estimate attacker effort."""
        easy_types = {"MemberOf", "AdminTo", "HasSession", "ForceChangePassword"}
        medium_types = {"GenericAll", "WriteDACL", "WriteOwner", "AddMember"}

        if all(e.edge_type in easy_types for e in edges):
            return "low"
        if any(e.edge_type in medium_types for e in edges):
            return "medium"
        return "high"

    def _describe_path(self, edges: List[Edge], source: str, target: str) -> str:
        """Generate human-readable path description."""
        src_name = self.nodes.get(source, Node("", "", "")).display_name
        tgt_name = self.nodes.get(target, Node("", "", "")).display_name

        steps = []
        for e in edges:
            src_n = self.nodes.get(e.source_id, Node("", "", "")).display_name
            tgt_n = self.nodes.get(e.target_id, Node("", "", "")).display_name
            steps.append(f"{src_n} --[{e.edge_type}]--> {tgt_n}")

        return f"Path from {src_name} to {tgt_name}:\n  " + "\n  ".join(steps)

    # ── Auto-execution helpers ─────────────────────────────────────────────

    def _can_auto_exec(self, edges: List[Edge]) -> bool:
        """Check if this path can be auto-executed by existing modules."""
        edge_types = {e.edge_type for e in edges}
        auto_executable = {
            "MemberOf", "AdminTo", "HasSession", "ForceChangePassword",
            "GenericAll", "WriteDACL", "AllowedToDelegate", "ExecuteDCOM",
        }
        return bool(edge_types & auto_executable)

    def _auto_exec_module(self, edges: List[Edge]) -> str:
        """Determine which Armagedon module to use for this path."""
        edge_types = [e.edge_type for e in edges]

        if "ForceChangePassword" in edge_types:
            return "auxiliary/password_spray"
        if "HasSession" in edge_types:
            return "post/credential_dump"
        if "AdminTo" in edge_types:
            return "post/ad_post_enum"
        if "AllowedToDelegate" in edge_types:
            return "auxiliary/kerberos_attack"
        if any(e in edge_types for e in ["GenericAll", "WriteDACL"]):
            return "auxiliary/ldap_enum"
        if "MemberOf" in edge_types:
            return "post/ad_post_enum"
        return "post/ad_post_enum"

    def _auto_exec_options(self, edges: List[Edge], source_sid: str) -> dict:
        """Build options dict for the auto-exec module."""
        source_node = self.nodes.get(source_sid)
        target_node = None

        # Find the last target in the path
        for e in edges:
            if e.target_id in self.high_value_nodes:
                target_node = self.nodes.get(e.target_id)
                break

        opts = {}
        if target_node and target_node.object_type == "computer":
            opts["RHOSTS"] = target_node.properties.get("dnshostname", "")
        if source_node:
            opts["USERNAME"] = source_node.name.split("\\")[-1].split("@")[0]
            opts["DOMAIN"] = source_node.properties.get("domain", "")
        return opts

    def _deduplicate_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Remove duplicate paths (same source, target, and edge types)."""
        seen = set()
        unique = []
        for p in paths:
            key = (p.source, p.target, tuple(e.edge_type for e in p.edges))
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    def _rank_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Rank paths: critical > high > medium, then low effort > medium > high."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        effort_order = {"low": 0, "medium": 1, "high": 2}
        return sorted(
            paths,
            key=lambda p: (
                severity_order.get(p.severity, 3),
                effort_order.get(p.effort, 2),
                len(p.edges),
            ),
        )

    # ── Reporting ──────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return summary statistics."""
        if not self._loaded:
            return {"error": "No data loaded"}

        type_counts = defaultdict(int)
        for n in self.nodes.values():
            type_counts[n.object_type] += 1

        edge_type_counts = defaultdict(int)
        for e in self.edges:
            edge_type_counts[e.edge_type] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": dict(type_counts),
            "edge_types": dict(edge_type_counts),
            "high_value_targets": len(self.high_value_nodes),
            "users": len(self.users) or type_counts.get("user", 0),
            "groups": len(self.groups) or type_counts.get("group", 0),
            "computers": len(self.computers) or type_counts.get("computer", 0),
            "attack_paths": len(self.attack_paths),
        }

    def export_paths(self, filepath: str):
        """Export attack paths to JSON."""
        data = []
        for p in self.attack_paths:
            src = self.nodes.get(p.source, Node("", "", ""))
            tgt = self.nodes.get(p.target, Node("", "", ""))
            data.append({
                "source": src.display_name,
                "source_sid": p.source,
                "target": tgt.display_name,
                "target_sid": p.target,
                "path_type": p.path_type,
                "severity": p.severity,
                "effort": p.effort,
                "description": p.description,
                "auto_executable": p.auto_executable,
                "auto_exec_module": p.auto_exec_module,
                "auto_exec_options": p.auto_exec_options,
                "edges": [
                    {
                        "from": self.nodes.get(e.source_id, Node("", "", "")).display_name,
                        "to": self.nodes.get(e.target_id, Node("", "", "")).display_name,
                        "type": e.edge_type,
                    }
                    for e in p.edges
                ],
            })
        Path(filepath).write_text(json.dumps(data, indent=2))
        log.info("Exported %d paths to %s", len(data), filepath)

    def print_paths(self, max_display: int = 20):
        """Print attack paths to console."""
        severity_colors = {
            "critical": "\033[91m",  # red
            "high": "\033[93m",      # yellow
            "medium": "\033[96m",    # cyan
            "low": "\033[92m",       # green
        }
        reset = "\033[0m"

        print(f"\n{'='*70}")
        print(f"  BLOODHOUND ATTACK PATH ANALYSIS — {len(self.attack_paths)} paths found")
        print(f"{'='*70}\n")

        for i, p in enumerate(self.attack_paths[:max_display], 1):
            color = severity_colors.get(p.severity, "")
            src = self.nodes.get(p.source, Node("", "", "")).display_name
            tgt = self.nodes.get(p.target, Node("", "", "")).display_name

            print(f"{color}  [{i}] {p.severity.upper()} | {p.path_type} | Effort: {p.effort}{reset}")
            print(f"      {src} → {tgt}")
            # Print individual hops
            for edge in p.edges:
                sn = self.nodes.get(edge.source_id, Node("", "", "")).display_name
                tn = self.nodes.get(edge.target_id, Node("", "", "")).display_name
                print(f"        {sn} --[{edge.edge_type}]--> {tn}")
            print(f"      Module: {p.auto_exec_module or 'N/A'}")
            if p.auto_executable:
                print(f"      {color}AUTO-EXECUTABLE{reset}")
            print()

        if len(self.attack_paths) > max_display:
            print(f"  ... and {len(self.attack_paths) - max_display} more paths")
        print(f"{'='*70}\n")
