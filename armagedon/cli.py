#!/usr/bin/env python3
"""
ARMAGEDON — Advanced Windows Exploitation Framework CLI.
Entry point for console_scripts: armagedon
"""
import sys
import os
import argparse
import signal
import readline
import atexit
from pathlib import Path

from armagedon.core.engine import ArmagedonEngine
from armagedon.core.database import Database
from armagedon.core.pipeline import ExploitPipeline
from armagedon.core.auto_privesc import AutoPrivesc
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  █████╗ ██████╗ ███╗   ███╗ █████╗  ██████╗ ███████╗██████╗  ║
║ ██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝ ██╔════╝██╔══██╗ ║
║ ███████║██████╔╝██╔████╔██║███████║██║  ███╗█████╗  ██║  ██║ ║
║ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║██║   ██║██╔══╝  ██║  ██║ ║
║ ██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗██████╔╝ ║
║ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝  ║
║     Windows Exploitation Framework — v1.0.0                    ║
║     "Fall of the walled garden"                                ║
╚══════════════════════════════════════════════════════════════════╝
"""


class ArmagedonCLI:
    def __init__(self):
        self.engine = ArmagedonEngine()
        self.db = Database()
        self.running = True
        self.history_file = os.path.expanduser("~/.armagedon_history")
        self._setup_completion()
        self._load_history()

    def _setup_completion(self):
        try:
            readline.set_completer(self._complete)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    def _load_history(self):
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
        except Exception:
            pass

    def _save_history(self):
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass

    def _complete(self, text, state):
        commands = [
            "help", "?", "exit", "quit", "back", "show", "set", "use", "run",
            "check", "search", "scan", "target", "info", "options",
        ]
        module_names = [m["name"] for m in self.engine.modules]
        buffer = readline.get_line_buffer()
        parts = buffer.split()

        if not parts:
            results = commands
        elif parts[0] in ("use",):
            prefix = parts[-1] if len(parts) > 1 else ""
            results = [m for m in module_names if m.startswith(prefix)]
        elif parts[0] in ("set",):
            if len(parts) == 1:
                results = list(self.engine.active_module.get("options", {}).keys()) if self.engine.active_module else []
            else:
                prefix = parts[-1].lower()
                opts = list(self.engine.active_module.get("options", {}).keys()) if self.engine.active_module else []
                results = [o for o in opts if o.lower().startswith(prefix)]
        else:
            results = [c for c in commands if c.startswith(text)]

        results = [r + " " for r in results]
        try:
            return results[state]
        except IndexError:
            return None

    def _get_banner(self):
        return BANNER

    def get_input(self, prompt="armagedon > "):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return "exit"

    def do_help(self, _=None):
        console.print(Panel.fit("""
[bold]Armagedon Commands[/]

[bold cyan]Core[/]
  help, ?         Show this help
  exit, quit      Exit Armagedon
  back            Return to main menu

[bold cyan]Target & Module[/]
  show modules    List all available modules
  show options    Show current module options
  use <module>    Select a module by name
  set <opt> <val> Set a module option
  run             Execute the current module
  check           Check if target is vulnerable
  search <query>  Search modules by name/CVE

[bold cyan]Nexus (Auto-Exploit)[/]
  nexus <target>          Full auto: scan → recommend → exploit
  nexus scan <target>     Scan only (no exploit)
  nexus recommend <target> Scan + recommend only
  privesc                 Interactive privilege escalation
  privesc auto            Auto-escalate (low→high risk)

[bold cyan]Scan[/]
  scan <target> <ports>  Quick port scan
  info            Show current module info

[bold cyan]Examples[/]
  use exploits/cve_2024_38077_madlicense_eop
  set RHOSTS 192.168.1.100
  set MODE CHECK
  run
""", title="Armagedon v1.0.0", border_style="bold red"))

    def do_exit(self, _=None):
        self.running = False
        raise SystemExit(0)

    do_quit = do_exit

    def do_back(self, _=None):
        self.engine.active_module = None
        console.print("[*] Returned to main menu")

    def do_show(self, arg):
        if not arg:
            console.print("[yellow]Usage: show [modules|options|info][/]")
            return
        arg = arg.strip().lower()
        if arg == "modules":
            self._show_modules()
        elif arg == "options":
            self._show_options()
        elif arg == "info":
            self._show_info()
        else:
            console.print(f"[yellow]Unknown show subcommand: {arg}[/]")

    def _show_modules(self):
        if not self.engine.modules:
            console.print("[yellow]No modules loaded[/]")
            return
        table = Table(title="Available Modules", box=None)
        table.add_column("#", style="dim", width=3)
        table.add_column("Name", style="cyan")
        table.add_column("CVE", style="yellow")
        table.add_column("Rank", style="green")
        table.add_column("Description", width=50)
        for i, m in enumerate(self.engine.modules, 1):
            table.add_row(
                str(i),
                m["name"],
                m.get("cve", "N/A"),
                m.get("rank", "normal"),
                m.get("desc", "")[:50],
            )
        console.print(table)
        console.print(f"\n[dim]Total: {len(self.engine.modules)} modules[/]")

    def _show_options(self):
        if not self.engine.active_module:
            console.print("[yellow]No module selected (use <module_name> first)[/]")
            return
        opts = self.engine.active_module.get("options", {})
        reqs = self.engine.active_module.get("required", {})
        descs = self.engine.active_module.get("descriptions", {})
        table = Table(title=f"Options for {self.engine.active_module['name']}", box=None)
        table.add_column("Name", style="cyan")
        table.add_column("Current Value", style="green")
        table.add_column("Required", style="red")
        table.add_column("Description", width=50)
        for k, v in opts.items():
            required = "[bold red]yes[/]" if reqs.get(k, False) else "no"
            desc = descs.get(k, "")[:50]
            display = str(v) if v else "(empty)"
            table.add_row(k, display, required, desc)
        console.print(table)

    def _show_info(self):
        if not self.engine.active_module:
            console.print("[yellow]No module selected[/]")
            return
        m = self.engine.active_module
        console.print(Panel.fit(
            f"[bold]Name:[/]         {m['name']}\n"
            f"[bold]CVE:[/]          {m.get('cve', 'N/A')}\n"
            f"[bold]Rank:[/]         {m.get('rank', 'normal')}\n"
            f"[bold]Platform:[/]     {m.get('platform', 'Windows')}\n"
            f"[bold]Author:[/]       {m.get('author', 'Unknown')}\n"
            f"[bold]Disclosure:[/]   {m.get('disclosure', 'Unknown')}\n"
            f"[bold]Description:[/]  {m.get('desc', 'No description')}",
            title=f"Module: {m['name']}"
        ))

    def do_use(self, module_name):
        if not module_name:
            console.print("[yellow]Usage: use <module_name>[/]")
            return
        if self.engine.load_module(module_name):
            console.print(f"[green][*][/] Using module: [bold]{self.engine.active_module['name']}[/]")
        else:
            console.print(f"[red][!][/] Module not found: {module_name}")
            self._show_similar(module_name)

    def _show_similar(self, query):
        results = self.engine.search_modules(query)
        if results:
            console.print("[yellow]Did you mean:[/]")
            for m in results:
                console.print(f"  [cyan]{m['name']}[/]")

    def do_set(self, arg):
        if not self.engine.active_module:
            console.print("[yellow]No module selected[/]")
            return
        parts = arg.split(None, 1)
        if len(parts) < 2:
            console.print("[yellow]Usage: set <option> <value>[/]")
            return
        opt, val = parts[0].upper(), parts[1]
        if self.engine.set_module_option(opt, val):
            console.print(f"[green][*][/] {opt} => {val}")
        else:
            console.print(f"[red][!][/] Unknown option: {opt}")

    def do_run(self, _=None):
        if not self.engine.active_module:
            console.print("[yellow]No module selected[/]")
            return
        if not self.engine.current_target:
            console.print("[yellow]No target set (use set RHOSTS <target>)[/]")
            return

        module_name = self.engine.active_module["name"]
        console.print(f"\n[bold cyan][*][/] Running module [bold]{module_name}[/] against [bold]{self.engine.current_target}[/]\n")

        try:
            result = self.engine.run_module()
            self._show_result(result)
        except Exception as e:
            import traceback
            console.print(f"[bold red][!][/] Module execution error: {e}")
            if self.engine.active_module.get("options", {}).get("VERBOSE"):
                console.print(f"[dim]{traceback.format_exc()}[/]")

    def _show_result(self, result):
        if not isinstance(result, dict):
            console.print(f"[yellow]Result: {result}[/]")
            return
        success = result.get("success", False)
        symbol = "[bold green][+][/]" if success else "[bold red][-][/]"
        console.print(f"\n{symbol} Module finished")
        for k, v in result.items():
            if k in ("success", "traceback"):
                continue
            color = "green" if k in ("vulnerable", "impact") else "white"
            console.print(f"  [bold]{k}:[/] [{color}]{v}[/]")
        if result.get("traceback"):
            console.print(f"  [dim]Traceback:[/]\n  [red]{result['traceback']}[/]")

    def do_check(self, _=None):
        if not self.engine.active_module:
            console.print("[yellow]No module selected[/]")
            return
        if not self.engine.current_target:
            console.print("[yellow]No target set[/]")
            return
        console.print("[*] Running check...")
        result = self.engine.check_module()
        if result is True:
            console.print("[bold green][+][/] Target is VULNERABLE")
        elif result is False:
            console.print("[bold red][-][/] Target is NOT vulnerable")
        elif result is None:
            console.print("[yellow][!][/] Module does not implement check()")

    def do_search(self, query):
        if not query:
            console.print("[yellow]Usage: search <query>[/]")
            return
        results = self.engine.search_modules(query)
        if results:
            console.print(f"[green][*][/] Found {len(results)} module(s):")
            for m in results:
                console.print(f"  [cyan]{m['name']}[/]  ({m.get('cve', 'N/A')})")
        else:
            console.print("[yellow]No modules found[/]")

    def do_scan(self, arg):
        parts = arg.split()
        if len(parts) < 1:
            console.print("[yellow]Usage: scan <target> [ports][/]")
            return
        target = parts[0]
        ports = parts[1] if len(parts) > 1 else "445,139,3389,5985,5986,135,389,636,88,443,80"
        console.print(f"[*] Scanning {target} on ports {ports}...")
        results = self.engine.quick_scan(target, ports)
        if results:
            table = Table(title=f"Scan Results: {target}", box=None)
            table.add_column("Port", style="cyan")
            table.add_column("State", style="green")
            table.add_column("Service", style="yellow")
            table.add_column("Banner", width=60)
            for r in results:
                table.add_row(str(r["port"]), r["state"], r["service"], r.get("banner", ""))
            console.print(table)
        else:
            console.print("[yellow][!][/] No open ports found")

    def do_target(self, target):
        if not target:
            console.print("[yellow]Usage: target <ip>[/]")
            return
        self.engine.set_target(target)
        console.print(f"[green][*][/] Target set to {target}")

    def do_nexus(self, arg):
        """Nexus mode: auto scan → recommend → exploit pipeline."""
        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: nexus <target>  |  nexus scan <target>  |  nexus recommend <target>[/]")
            return

        subcmd = parts[0].lower()
        target = ""
        if subcmd in ("scan", "recommend", "auto"):
            if len(parts) < 2:
                console.print(f"[yellow]Usage: nexus {subcmd} <target>[/]")
                return
            target = parts[1]
        else:
            target = parts[0]
            subcmd = "auto"

        pipeline = ExploitPipeline(self.engine)

        if subcmd == "scan":
            results = pipeline.run_scan(target)
            pipeline.display_scan_results(results)
        elif subcmd == "recommend":
            results = pipeline.run_scan(target)
            pipeline.display_scan_results(results)
            pipeline.run_recommend()
        else:
            pipeline.auto_pwn(target)

    def do_privesc(self, arg):
        """Privilege escalation orchestrator."""
        privesc = AutoPrivesc(target=self.engine.current_target or "")

        if arg.strip().lower() == "auto":
            privesc.auto_escalate()
        else:
            privesc.interactive_run()

    do_info = lambda self, _: self._show_info()
    do_question_mark = do_help

    def run(self):
        console.print(BANNER)
        console.print(f"[dim]Loaded {len(self.engine.modules)} modules | {len(self.engine.modules)} exploits available[/]\n")

        if not self.engine.current_target:
            console.print("[dim]Tip: set a target with 'set RHOSTS <ip>' or 'target <ip>'[/]")

        while self.running:
            try:
                cmd_parts = self.get_input().split(None, 1)
                if not cmd_parts or not cmd_parts[0]:
                    continue
                cmd = cmd_parts[0].lower()
                arg = cmd_parts[1] if len(cmd_parts) > 1 else ""

                handler_map = {
                    "help": self.do_help, "?": self.do_help,
                    "exit": self.do_exit, "quit": self.do_exit,
                    "back": self.do_back,
                    "show": self.do_show,
                    "use": self.do_use,
                    "set": self.do_set,
                    "run": self.do_run,
                    "check": self.do_check,
                    "search": self.do_search,
                    "scan": self.do_scan,
                    "target": self.do_target,
                    "info": self.do_info,
                    "options": lambda _: self.do_show("options"),
                    "modules": lambda _: self.do_show("modules"),
                    "nexus": self.do_nexus,
                    "privesc": self.do_privesc,
                }

                handler = handler_map.get(cmd)
                if handler:
                    handler(arg)
                else:
                    similar = self.engine.search_modules(cmd)
                    if similar:
                        self.do_use(cmd)
                    else:
                        console.print(f"[red][!][/] Unknown command: {cmd}")
                        console.print("[dim]Type 'help' for available commands[/]")
            except SystemExit:
                break
            except Exception as e:
                console.print(f"[red][!][/] Error: {e}")

        self._save_history()
        console.print("\n[bold red][*][/] Armagedon shutting down...")


def main():
    parser = argparse.ArgumentParser(description="Armagedon — Windows Exploitation Framework")
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-m", "--module", help="Module to run (non-interactive)")
    parser.add_argument("-s", "--scan", help="Quick scan mode: target:port")
    parser.add_argument("--nexus", nargs="?", const=True, default=None,
                        help="Nexus auto-exploit mode: --nexus <target>")
    parser.add_argument("--recommend", help="Scan + recommend exploits for target")
    parser.add_argument("--privesc", action="store_true", help="Run privilege escalation")
    parser.add_argument("-o", "--output", help="Output directory for results")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")

    args = parser.parse_args()

    cli = ArmagedonCLI()

    if args.target:
        cli.engine.set_target(args.target)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        cli.engine.output_dir = args.output

    if args.nexus:
        target = args.nexus if isinstance(args.nexus, str) else args.target
        if not target:
            console.print("[red]Nexus mode requires a target (--nexus <target> or --target <ip>)[/]")
            return
        cli.do_nexus(target)
        return

    if args.recommend:
        cli.do_nexus(f"recommend {args.recommend}")
        return

    if args.privesc:
        cli.do_privesc("interactive")
        return

    if args.scan:
        target_info = args.scan.split(":")
        target = target_info[0]
        ports = target_info[1] if len(target_info) > 1 else "445,139,3389,5985,5986,135,389,636,88,443,80"
        cli.do_scan(f"{target} {ports}")
        return

    if args.module:
        cli.do_use(args.module)
        if args.quiet:
            cli.do_run()
        else:
            cli.run()
    else:
        cli.run()


if __name__ == "__main__":
    main()
