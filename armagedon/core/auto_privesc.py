"""Automatic privilege escalation orchestrator.
Discovers and runs applicable privesc modules on a compromised host."""

import importlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()


PRIVESC_MODULES = {
    "token_steal": {
        "name": "Token Stealing",
        "description": "Duplicate SYSTEM token from Winlogon/LSASS",
        "requirements": ["admin"],
        "risk": "medium",
    },
    "uac_bypass": {
        "name": "UAC Bypass",
        "description": "Bypass UAC via eventvwr / fodhelper",
        "requirements": ["local_admin"],
        "risk": "low",
    },
    "service_privesc": {
        "name": "Service Path Exploitation",
        "description": "Exploit weak service permissions or unquoted paths",
        "requirements": ["local"],
        "risk": "medium",
    },
    "stored_creds": {
        "name": "Stored Credentials",
        "description": "Extract saved creds, vault, WLAN passwords",
        "requirements": ["local"],
        "risk": "low",
    },
}


class AutoPrivesc:
    """Orchestrate privilege escalation on a target."""

    def __init__(self, target: str = "", session_id: str = ""):
        self.target = target
        self.session_id = session_id
        self.results = {}

    def list_privesc_modules(self) -> list:
        """Return available privesc modules."""
        modules = []
        for mod_id, meta in PRIVESC_MODULES.items():
            modules.append({
                "id": mod_id,
                **meta,
            })
        return modules

    def display_privesc_options(self):
        """Print privesc modules table."""
        table = Table(title="Privilege Escalation Modules")
        table.add_column("#", style="cyan")
        table.add_column("Module", style="yellow")
        table.add_column("Description", style="white")
        table.add_column("Risk", style="red")
        table.add_column("Requirements", style="blue")

        for i, m in enumerate(self.list_privesc_modules(), 1):
            table.add_row(
                str(i),
                m["id"],
                m["description"],
                m["risk"],
                ", ".join(m["requirements"]),
            )

        console.print(table)
        return table

    def run_module(self, module_id: str, **kwargs) -> dict:
        """Execute a specific privesc module."""
        console.print(
            Panel(
                f"[bold yellow]Running privesc: {module_id}[/]",
                border_style="yellow",
            )
        )

        result = {"success": False, "data": None, "error": None}

        try:
            mod = importlib.import_module(
                f"armagedon.modules.privesc.{module_id}"
            )
            if hasattr(mod, "run"):
                out = mod.run(target=self.target, **kwargs)
                result["success"] = out.get("success", False)
                result["data"] = out
            else:
                result["error"] = "Module has no run() function"
        except ImportError:
            result["error"] = f"Module {module_id} not found"
        except Exception as e:
            result["error"] = str(e)

        if result["error"]:
            console.print(f"[red]Privesc failed: {result['error']}[/]")
        else:
            status = "[green]SYSTEM access gained[/]" if result.get("success") else "[yellow]Failed[/]"
            console.print(f"{status}")

        self.results[module_id] = result
        return result

    def interactive_run(self):
        """List modules, let user pick one, execute it."""
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

    def auto_escalate(self, current_privilege: str = "user") -> dict:
        """Auto-try privesc modules in order of risk, stop when SYSTEM."""
        console.print(
            Panel(
                "[bold yellow]Auto privilege escalation engaged...[/]",
                border_style="yellow",
            )
        )

        results_summary = []

        risk_order = ["low", "medium", "high"]
        for risk in risk_order:
            for mod_id, meta in PRIVESC_MODULES.items():
                if meta["risk"] != risk:
                    continue
                console.print(
                    f"  Trying [cyan]{mod_id}[/] ({meta['risk']} risk)..."
                )
                result = self.run_module(mod_id)
                results_summary.append({
                    "module": mod_id,
                    "success": result.get("success", False),
                })
                if result.get("success"):
                    console.print(
                        f"[bold green]Escalated via {mod_id}![/]"
                    )
                    return {
                        "status": "escalated",
                        "module": mod_id,
                        "results": results_summary,
                    }

        console.print("[red]All privesc attempts failed.[/]")
        return {
            "status": "failed",
            "module": None,
            "results": results_summary,
        }
