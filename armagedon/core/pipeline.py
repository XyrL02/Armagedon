"""Exploit pipeline — scan → recommend → exploit → privesc chain."""

import importlib
import sys
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from armagedon.core.recommender import Recommender
from armagedon.core.database import Database

console = Console()


class ExploitPipeline:
    """Orchestrates the full attack chain for a target."""

    def __init__(self, engine=None):
        self.engine = engine
        self.recommender = Recommender(engine)
        self.db = Database()
        self.scan_results = {}
        self.target = ""

    def run_scan(self, target: str, ports: str = None) -> dict:
        """Phase 1: Scan the target for open ports, OS, services."""
        self.target = target
        console.print(Panel(f"[bold cyan]Nexus Scan[/] — {target}", border_style="cyan"))

        results = {
            "target": target,
            "open_ports": [],
            "os": "",
            "build": 0,
            "protocols": {},
            "hotfixes": [],
            "services": {},
            "smb_info": {},
            "rdp_info": {},
            "raw": {},
        }

        scanner = None
        try:
            mod = importlib.import_module(
                "armagedon.modules.scanners.smb_scanner"
            )
            scanner = mod.SMBScanner()
        except Exception:
            pass

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            scan_port = progress.add_task(
                f"[cyan]Probing ports on {target}...", total=None
            )

            if scanner and hasattr(scanner, "quick_scan"):
                try:
                    pr = scanner.quick_scan(target, ports or "135,139,445,3389,5985,5986,389,88,593")
                    results["open_ports"] = pr.get("open_ports", [])
                    results["smb_info"] = pr.get("smb_info", {})
                    results["services"] = pr.get("services", {})
                    raw_os = pr.get("os", "")
                    if raw_os:
                        results["os"] = raw_os
                        results["build"] = pr.get("build", 0)
                        results["protocols"] = pr.get("protocols", {})
                        results["hotfixes"] = pr.get("hotfixes", [])
                except Exception:
                    pass
            progress.remove_task(scan_port)

        self.scan_results = results
        self.db.save_host(target, results)

        return results

    def display_scan_results(self, results: dict):
        """Phase 1b: Show scan summary."""
        table = Table(title=f"Scan Results — {results['target']}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        os_info = results.get("os", "Unknown")
        build = results.get("build", 0)
        ports = ", ".join(str(p) for p in results.get("open_ports", []))
        smb_signing = results.get("smb_info", {}).get("signing", "?")
        smb_ver = results.get("smb_info", {}).get("version", "?")

        table.add_row("Operating System", os_info)
        if build:
            table.add_row("Build", str(build))
        table.add_row("Open Ports", ports or "None detected")
        if smb_ver:
            table.add_row("SMB Version", smb_ver)
        if smb_signing:
            table.add_row("SMB Signing", smb_signing)

        console.print(table)
        return table

    def run_recommend(self) -> list:
        """Phase 2: Recommend exploits based on scan data."""
        console.print(
            Panel(
                "[bold yellow]Analyzing target and matching exploits...[/]",
                border_style="yellow",
            )
        )
        candidates = self.recommender.recommend(
            self.target, self.scan_results, top_n=8
        )
        self.recommender.display_recommendations(self.target, candidates)
        return candidates

    def run_exploit(self, module_name: str, mode: str = "check") -> dict:
        """Phase 3: Execute a specific exploit module."""
        console.print(
            Panel(
                f"[bold red]Launching exploit: {module_name}[/] ({mode})",
                border_style="red",
            )
        )

        result = {
            "success": False,
            "data": {},
            "session": None,
            "error": None,
        }

        try:
            mod = importlib.import_module(
                f"armagedon.modules.exploits.{module_name}"
            )

            if hasattr(mod, "run"):
                if mode == "check":
                    out = mod.run(target=self.target, mode="CHECK")
                elif mode == "exploit":
                    out = mod.run(target=self.target, mode="EXPLOIT")
                else:
                    out = mod.run(target=self.target, mode=mode.upper())

                result["success"] = True
                result["data"] = out
                result["mode"] = mode

                self.db.log_finding(
                    target=self.target,
                    module=module_name,
                    success=result["success"],
                    data=str(out)[:500],
                )
            else:
                result["error"] = "Module has no run() function"

        except ImportError as e:
            result["error"] = f"Module not found: {e}"
        except Exception as e:
            result["error"] = str(e)
            self.db.log_finding(
                target=self.target,
                module=module_name,
                success=False,
                data=str(e)[:500],
            )

        if result["error"]:
            console.print(f"[red]Exploit failed: {result['error']}[/]")
        else:
            console.print(
                f"[green]Exploit completed ({mode}).[/]"
            )

        return result

    def auto_pwn(self, target: str, ports: str = None) -> dict:
        """Full auto chain: scan → recommend → execute."""
        console.print(
            Panel.fit(
                "[bold red]A R M A G E D O N — N E X U S   M O D E[/]\n"
                "[yellow]Automated exploitation pipeline[/]",
                border_style="red",
            )
        )

        results = self.run_scan(target, ports)
        self.display_scan_results(results)

        if not results.get("open_ports"):
            console.print("[red]No open ports detected. Aborting.[/]")
            return {"status": "failed", "reason": "no_open_ports"}

        candidates = self.run_recommend()
        if not candidates:
            console.print("[red]No applicable exploits found.[/]")
            return {"status": "failed", "reason": "no_exploits"}

        top = candidates[0]
        console.print(
            f"\n[bold green]Best match:[/] {top['cve']} — {top['name']} "
            f"(Score: {top['score']})"
        )

        return {
            "status": "complete",
            "target": target,
            "top_exploit": top,
            "all_candidates": candidates,
            "scan": results,
        }
