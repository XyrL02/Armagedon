#!/usr/bin/env python3
"""
ARMAGEDON — Advanced Windows Exploitation Framework CLI.
Entry point for console_scripts: armagedon
"""
import sys
import os
import logging
import argparse
import signal
import readline
import atexit
from pathlib import Path

log = logging.getLogger("armagedon.cli")

from armagedon.core.engine import ArmagedonEngine
from armagedon.core.database import Database
from armagedon.core.pipeline import ExploitPipeline
from armagedon.core.auto_privesc import AutoPrivesc
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

BANNER = r"""
    _    ____  __  __    _    ____ _____ ____   ___  _   _ 
   / \  |  _ \|  \/  |  / \  / ___| ____|  _ \ / _ \| \ | |
  / _ \ | |_) | |\/| | / _ \| |  _|  _| | | | | | | |  \| |
 / ___ \|  _ <| |  | |/ ___ \ |_| | |___| |_| | |_| | |\  |
/_/   \_\_| \_\_|  |_/_/   \_\____|_____|____/ \___/|_| \_|
         Windows Exploitation Framework — v1.0.0
              "Fall of the walled garden"
"""


class ArmagedonCLI:
    def __init__(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )
        log.info("Armagedon CLI initializing")
        self.engine = ArmagedonEngine()
        self.db = Database()
        self.running = True
        self.history_file = os.path.expanduser("~/.armagedon_history")
        self._setup_completion()
        self._load_history()
        log.debug("CLI ready — history=%s", self.history_file)

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
            "nexus", "privesc", "ad_post_enum", "bloodhound",
            "domain", "constrained_delegation", "ccache_to_shell", "secretsdump_bypass",
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
  privesc                 Interactive privilege escalation picker
  privesc auto            Auto-detect priv + try all modules (low→high risk)
  privesc auto -u U -p P -d D     Auto with remote privilege detection
  privesc bh <dir> [--source SID]  BloodHound-driven escalation chain

[bold cyan]AD Post-Enum[/]
  ad_post_enum <target> -u user -p pass -d domain  Full AD post-exploitation loop

[bold cyan]Constrained Delegation / Kerberos[/]
  constrained_delegation <target> -u user -p pass -d domain [--spn SPN] [--mode ENUM|EXPLOIT]
  ccache_to_shell <target> -d domain --ticket <ccache> [--method auto|smbexec|smbclient|evil-winrm]
  secretsdump_bypass <target> -d domain --ticket <ccache> [--method auto|secretsdump_standard|secretsdump_vss]

[bold cyan]BloodHound[/]
  bloodhound <dir> [--source user] [--mode analyze|exploit] [--auto-exec]  Analyze BH data

[bold cyan]Domain Intelligence & Attack[/]
  domain ingest <dir> [-d domain] [-u user] [-p pass]     Ingest ldapdomaindump output
  domain ingest-bh <dir>                                   Ingest BloodHound JSON
  domain ingest-live <target> -u user -p pass -d domain    Live LDAP enumeration
  domain whoami                                            Show current user analysis
  domain whoami <user>                                     Show target user analysis
  domain path                                              Find shortest path to DA
  domain path <user>                                       Find path from user to DA
  domain attack <user> <target> -u user -p pass -d domain  Execute best attack
  domain recommend                                         Show available attacks for current user
  domain export <file>                                     Export domain graph to JSON

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
        """Privilege escalation orchestrator.

        Usage:
          privesc                          Interactive module picker
          privesc auto                     Auto-detect priv + try all modules
          privesc auto -u U -p P -d D     Auto with remote privilege detection
          privesc bh <dir> [--source SID]  BloodHound-driven escalation chain
        """
        from armagedon.core.auto_privesc import AutoPrivesc

        parts = arg.split()
        privesc = AutoPrivesc(target=self.engine.current_target or "")

        if not parts:
            privesc.interactive_run()
            return

        subcmd = parts[0].lower()

        if subcmd == "auto":
            user = passwd = domain = ""
            i = 1
            while i < len(parts):
                if parts[i] == "-u" and i + 1 < len(parts):
                    user = parts[i + 1]; i += 2
                elif parts[i] == "-p" and i + 1 < len(parts):
                    passwd = parts[i + 1]; i += 2
                elif parts[i] == "-d" and i + 1 < len(parts):
                    domain = parts[i + 1]; i += 2
                else:
                    i += 1

            result = privesc.auto_escalate(
                is_remote=bool(user),
                user=user, passwd=passwd, domain=domain,
            )
            console.print(f"\n[bold]Result:[/] {result['status']} | "
                          f"Final priv: {result.get('final_privilege', '?')}")

        elif subcmd == "bh":
            # BloodHound-driven chain: privesc bh <bh_dir> [--source SID]
            bh_dir = ""
            source_sid = ""
            user = passwd = domain = ""
            i = 1
            while i < len(parts):
                if parts[i] == "--source" and i + 1 < len(parts):
                    source_sid = parts[i + 1]; i += 2
                elif parts[i] == "-u" and i + 1 < len(parts):
                    user = parts[i + 1]; i += 2
                elif parts[i] == "-p" and i + 1 < len(parts):
                    passwd = parts[i + 1]; i += 2
                elif parts[i] == "-d" and i + 1 < len(parts):
                    domain = parts[i + 1]; i += 2
                elif not bh_dir:
                    bh_dir = parts[i]; i += 2
                else:
                    i += 1

            if not bh_dir:
                console.print("[yellow]Usage: privesc bh <bloodhound_dir> [--source SID] [-u user] [-p pass] [-d domain][/]")
                return

            from armagedon.core.bloodhound import BloodHoundAnalyzer
            analyzer = BloodHoundAnalyzer()
            if not analyzer.load_from_directory(bh_dir):
                console.print(f"[red]Failed to load BloodHound data from {bh_dir}[/]")
                return

            result = privesc.bloodhound_auto_escalate(
                analyzer, source_sid=source_sid,
                user=user, passwd=passwd, domain=domain,
            )
            console.print(f"\n[bold]Result:[/] {result['status']}")
        else:
            console.print("[yellow]Usage: privesc [auto|bh] [options][/]")

    def do_ad_post_enum(self, arg):
        """AD Post-Exploitation Enumeration — full automated AD post-exploitation loop."""
        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: ad_post_enum <target> [-u user] [-p pass] [-d domain] [--ntlm-hash hash] [--steps STEPS][/]")
            console.print("[dim]Example: ad_post_enum 10.10.10.1 -u admin -p Pass123 -d CORP.LOCAL[/]")
            console.print("[dim]Pass-the-hash: ad_post_enum 10.10.10.1 -u admin -H aad3b435... -d CORP.LOCAL[/]")
            return

        from armagedon.modules.post import ad_post_enum
        target_ip = parts[0]
        user = passwd = domain = ntlm_hash = ""
        mode = "FULL"
        steps = "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY,SHARE"

        i = 1
        while i < len(parts):
            if parts[i] == "-u" and i + 1 < len(parts):
                user = parts[i + 1]; i += 2
            elif parts[i] == "-p" and i + 1 < len(parts):
                passwd = parts[i + 1]; i += 2
            elif parts[i] == "-d" and i + 1 < len(parts):
                domain = parts[i + 1]; i += 2
            elif parts[i] in ("-H", "--ntlm-hash") and i + 1 < len(parts):
                ntlm_hash = parts[i + 1]; i += 2
            elif parts[i] == "--steps" and i + 1 < len(parts):
                steps = parts[i + 1]; i += 2
            elif parts[i] == "--mode" and i + 1 < len(parts):
                mode = parts[i + 1].upper()
                if mode == "FULL":
                    steps = "TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY,SHARE"
                else:
                    steps = mode
                i += 2
            else:
                i += 1

        if not user or not domain:
            console.print("[red][!][/] Required: -u <user> -d <domain> (-p pass OR -H hash)")
            return
        if not passwd and not ntlm_hash:
            console.print("[red][!][/] Provide either -p <pass> or -H <ntlm-hash>")
            return

        opts = {
            "RHOSTS": target_ip,
            "USERNAME": user,
            "PASSWORD": passwd,
            "NTLM_HASH": ntlm_hash,
            "DOMAIN": domain,
            "MODE": mode,
            "STEPS": steps,
        }
        self.engine.set_target(target_ip)
        auth_method = f"hash:{ntlm_hash[:16]}..." if ntlm_hash else f"pass:{passwd[:8]}..."
        console.print(f"\n[bold cyan][*][/] Running AD Post-Enum against [bold]{target_ip}[/] ({domain}\\{user}) [{auth_method}]\n")
        result = ad_post_enum.run(options=opts, mode="EXPLOIT")
        self._show_result(result)

    def do_bloodhound(self, arg):
        """BloodHound Attack Path Analyzer — load BH JSON, find privesc paths, auto-execute."""
        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: bloodhound <dir_or_file> [--source user] [--target sid] [--mode analyze|exploit] [--auto-exec][/]")
            console.print("[dim]Example: bloodhound ./loot/bloodhound --source visitor --mode exploit --auto-exec[/]")
            return

        from armagedon.modules.auxiliary import bloodhound_analyzer

        bh_path = parts[0]
        source = target_sid = ""
        mode = "ANALYZE"
        auto_exec = False
        max_depth = 6
        max_paths = 20

        i = 1
        while i < len(parts):
            if parts[i] == "--source" and i + 1 < len(parts):
                source = parts[i + 1]; i += 2
            elif parts[i] == "--target" and i + 1 < len(parts):
                target_sid = parts[i + 1]; i += 2
            elif parts[i] == "--mode" and i + 1 < len(parts):
                mode = parts[i + 1].upper(); i += 2
            elif parts[i] == "--auto-exec":
                auto_exec = True; i += 1
            elif parts[i] == "--max-depth" and i + 1 < len(parts):
                max_depth = int(parts[i + 1]); i += 2
            elif parts[i] == "--max-paths" and i + 1 < len(parts):
                max_paths = int(parts[i + 1]); i += 2
            else:
                i += 1

        # Determine if path is a directory or file
        bh_path_expanded = os.path.expanduser(bh_path)
        if os.path.isdir(bh_path_expanded):
            opts = {"BLOODHOUND_DIR": bh_path_expanded}
        elif os.path.isfile(bh_path_expanded):
            opts = {"BLOODHOUND_FILE": bh_path_expanded}
        else:
            console.print(f"[red][!][/] Not found: {bh_path}")
            return

        opts.update({
            "SOURCE_USER": source,
            "TARGET_SID": target_sid,
            "MODE": mode,
            "MAX_DEPTH": max_depth,
            "MAX_PATHS": max_paths,
            "AUTO_EXEC": auto_exec,
            "AUTO_EXEC_LIMIT": 5,
        })

        # Add credentials if available from current module options
        if self.engine.active_module:
            mod_opts = self.engine.active_module.get("options", {})
            for k in ("USERNAME", "PASSWORD", "DOMAIN"):
                if mod_opts.get(k):
                    opts[k] = mod_opts[k]

        console.print(f"\n[bold cyan][*][/] BloodHound Analyzer — mode: {mode}\n")
        result = bloodhound_analyzer.run(options=opts, mode=mode)
        self._show_result(result)

    def do_domain(self, arg):
        """Domain Intelligence & Attack — ingest AD data, analyze controls, execute attacks.

        Usage:
          domain ingest <dir> [-d domain] [-u user] [-p pass]     Ingest ldapdomaindump output
          domain ingest-bh <dir>                                   Ingest BloodHound JSON
          domain ingest-live <target> -u user -p pass -d domain    Live LDAP enumeration
          domain whoami                                            Show current user analysis
          domain whoami <user>                                     Show target user analysis
          domain path                                              Find shortest path to DA
          domain path <user>                                       Find path from user to DA
          domain attack <user> <target> -u user -p pass -d domain  Execute best attack
          domain recommend                                         Show available attacks
          domain export <file>                                     Export domain graph to JSON
        """
        from armagedon.core.domain_intel import DomainIntel

        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: domain [ingest|ingest-bh|ingest-live|whoami|path|attack|recommend|export] [options][/]")
            return

        subcmd = parts[0].lower()
        if not hasattr(self, '_domain_intel'):
            self._domain_intel = DomainIntel()

        intel = self._domain_intel

        if subcmd == "ingest":
            dir_path = parts[1] if len(parts) > 1 else ""
            if not dir_path or not Path(dir_path).is_dir():
                console.print("[red][!][/] Usage: domain ingest <ldapdomaindump_dir> [-d domain] [-u user] [-p pass][/]")
                return
            console.print(f"[*] Ingesting ldapdomaindump from {dir_path}...")
            intel.ingest_ldapdomaindump(dir_path)
            s = intel.summary()
            console.print(f"[+] Users: {s['object_types'].get('user',0)} | "
                          f"Groups: {s['object_types'].get('group',0)} | "
                          f"Computers: {s['object_types'].get('computer',0)} | "
                          f"ACLs: {s['acl_entries']}")

        elif subcmd == "ingest-bh":
            dir_path = parts[1] if len(parts) > 1 else ""
            if not dir_path or not Path(dir_path).is_dir():
                console.print("[red][!][/] Usage: domain ingest-bh <bloodhound_json_dir>[/]")
                return
            console.print(f"[*] Ingesting BloodHound JSON from {dir_path}...")
            intel.ingest_bloodhound_json(dir_path)
            s = intel.summary()
            console.print(f"[+] Users: {s['object_types'].get('user',0)} | "
                          f"Groups: {s['object_types'].get('group',0)} | "
                          f"Computers: {s['object_types'].get('computer',0)} | "
                          f"ACLs: {s['acl_entries']}")

        elif subcmd == "ingest-live":
            if len(parts) < 6:
                console.print("[red][!][/] Usage: domain ingest-live <target> -u user -p pass -d domain[/]")
                return
            target_ip = parts[1]
            user = passwd = domain = ""
            i = 2
            while i < len(parts):
                if parts[i] == "-u" and i + 1 < len(parts):
                    user = parts[i+1]; i += 2
                elif parts[i] == "-p" and i + 1 < len(parts):
                    passwd = parts[i+1]; i += 2
                elif parts[i] == "-d" and i + 1 < len(parts):
                    domain = parts[i+1]; i += 2
                else:
                    i += 1
            if not user or not passwd or not domain:
                console.print("[red][!][/] Need -u <user> -p <pass> -d <domain>[/]")
                return
            console.print(f"[*] Live LDAP enumeration against {target_ip} ({domain}\\{user})...")
            intel.ingest_live(target_ip, domain, user, passwd)
            s = intel.summary()
            console.print(f"[+] Users: {s['object_types'].get('user',0)} | "
                          f"Groups: {s['object_types'].get('group',0)} | "
                          f"Computers: {s['object_types'].get('computer',0)} | "
                          f"ACLs: {s['acl_entries']}")

        elif subcmd == "whoami":
            user = parts[1] if len(parts) > 1 else ""
            if not user:
                user = self.engine.active_module.get("options", {}).get("USERNAME", "") if self.engine.active_module else ""
            if not user:
                console.print("[red][!][/] Usage: domain whoami <username>[/]")
                return
            if not intel.summary().get("total_objects"):
                console.print("[yellow][!] No domain data loaded. Run domain ingest/ingest-bh first.[/]")
                return
            intel.print_whoami(user)
            intel.print_outbound_control(user)

        elif subcmd == "path":
            user = parts[1] if len(parts) > 1 else ""
            if not user:
                user = self.engine.active_module.get("options", {}).get("USERNAME", "") if self.engine.active_module else ""
            if not user:
                console.print("[red][!][/] Usage: domain path <username>[/]")
                return
            path = intel.find_shortest_path_to_da(user)
            if not path:
                console.print(f"[yellow]No path from {user} to Domain Admins found[/]")
            else:
                console.print(f"\n[bold green][+][/] Shortest path: {' -> '.join(path)}")

        elif subcmd == "attack":
            if len(parts) < 3:
                console.print("[red][!][/] Usage: domain attack <compromised_user> <target> -u user -p pass -d domain[/]")
                return
            user = parts[1]
            target = parts[2]
            user = passwd = domain = ""
            i = 3
            while i < len(parts):
                if parts[i] == "-u" and i + 1 < len(parts):
                    user = parts[i+1]; i += 2
                elif parts[i] == "-p" and i + 1 < len(parts):
                    passwd = parts[i+1]; i += 2
                elif parts[i] == "-d" and i + 1 < len(parts):
                    domain = parts[i+1]; i += 2
                else:
                    i += 1
            if not user or not passwd or not domain:
                console.print("[red][!][/] Need -u <user> -p <pass> -d <domain>[/]")
                return
            rec = intel.recommend_attack(user, target)
            console.print(f"\n[bold]Recommendation:[/] {rec.get('right','?')} on {rec.get('target','?')}")
            if "example_commands" in rec:
                console.print("[dim]Example commands:[/]")
                for cmd in rec["example_commands"]:
                    console.print(f"  {cmd}")
            dc_ip = self.engine.current_target or ""
            from armagedon.modules.auxiliary import domain_attack as da_mod
            opts = {"DC_IP": dc_ip, "DOMAIN": domain, "USERNAME": user,
                    "PASSWORD": passwd, "TARGET_USER": target, "MODE": "CHECK"}
            result = da_mod.run(options=opts, mode="CHECK")
            self._show_result(result)

        elif subcmd == "recommend":
            user = parts[1] if len(parts) > 1 else ""
            if not user:
                user = self.engine.active_module.get("options", {}).get("USERNAME", "") if self.engine.active_module else ""
            if not user:
                console.print("[red][!][/] Usage: domain recommend <username>[/]")
                return
            if not intel.summary().get("total_objects"):
                console.print("[yellow][!] No domain data loaded. Run domain ingest/ingest-bh first.[/]")
                return
            rec = intel.recommend_attack(user)
            console.print(f"\n[bold]Best attack:[/] {rec.get('right','?')} on {rec.get('target','?')}")
            if "example_commands" in rec:
                console.print("[dim]Example commands:[/]")
                for cmd in rec["example_commands"]:
                    console.print(f"  {cmd}")

        elif subcmd == "export":
            file_path = parts[1] if len(parts) > 1 else ""
            if not file_path:
                console.print("[red][!][/] Usage: domain export <output_file.json>[/]")
                return
            intel.export_json(file_path)
            console.print(f"[+] Exported to {file_path}")

        else:
            console.print(f"[red][!][/] Unknown subcommand: {subcmd}")
            console.print("[dim]Available: ingest, ingest-bh, ingest-live, whoami, path, attack, recommend, export[/]")

    def do_constrained_delegation(self, arg):
        """Constrained Delegation exploitation — S4U2Self/S4U2Proxy attack chain.

        Usage:
          constrained_delegation <target> -u user -p pass -d domain [--spn SPN] [--mode ENUM|EXPLOIT]
          constrained_delegation <target> -u user -p pass -d domain --ticket <ccache> --lateral-method smbexec
        """
        from armagedon.modules.exploits import exploit_constrained_delegation as cd_mod

        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: constrained_delegation <target> -u user -p pass -d domain [options][/]")
            console.print("[dim]Options: --spn SPN, --target-user USER, --ticket CCACHE, --lateral-method METHOD, --mode ENUM|EXPLOIT[/]")
            return

        target_ip = parts[0]
        user = passwd = domain = spn = target_user = ticket = lateral = ""
        mode = "ENUM"

        i = 1
        while i < len(parts):
            if parts[i] == "-u" and i + 1 < len(parts):
                user = parts[i + 1]; i += 2
            elif parts[i] == "-p" and i + 1 < len(parts):
                passwd = parts[i + 1]; i += 2
            elif parts[i] == "-d" and i + 1 < len(parts):
                domain = parts[i + 1]; i += 2
            elif parts[i] == "--spn" and i + 1 < len(parts):
                spn = parts[i + 1]; i += 2
            elif parts[i] == "--target-user" and i + 1 < len(parts):
                target_user = parts[i + 1]; i += 2
            elif parts[i] == "--ticket" and i + 1 < len(parts):
                ticket = parts[i + 1]; i += 2
            elif parts[i] == "--lateral-method" and i + 1 < len(parts):
                lateral = parts[i + 1]; i += 2
            elif parts[i] == "--mode" and i + 1 < len(parts):
                mode = parts[i + 1].upper(); i += 2
            else:
                i += 1

        opts = {
            "RHOSTS": target_ip, "DOMAIN": domain,
            "USERNAME": user, "PASSWORD": passwd,
            "TARGET_SPN": spn, "TARGET_USER": target_user or "Administrator",
            "TICKET_FILE": ticket,
            "LATERAL_SHELL": lateral or "smbexec",
        }

        console.print(f"\n[bold cyan][*][/] Constrained Delegation — {target_ip} ({domain})\n")
        result = cd_mod.run(options=opts, target=target_ip, mode=mode)
        self._show_result(result)

    def do_ccache_to_shell(self, arg):
        """Use a .ccache ticket for lateral movement.

        Usage:
          ccache_to_shell <target> -d domain --ticket <ccache> [--method auto|smbexec|smbclient|evil-winrm]
        """
        from armagedon.modules.exploits import exploit_ccache_to_shell as cs_mod

        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: ccache_to_shell <target> -d domain --ticket <ccache> [--method METHOD][/]")
            return

        target_ip = parts[0]
        domain = ticket = method = ""

        i = 1
        while i < len(parts):
            if parts[i] == "-d" and i + 1 < len(parts):
                domain = parts[i + 1]; i += 2
            elif parts[i] == "--ticket" and i + 1 < len(parts):
                ticket = parts[i + 1]; i += 2
            elif parts[i] == "--method" and i + 1 < len(parts):
                method = parts[i + 1]; i += 2
            else:
                i += 1

        if not ticket:
            console.print("[red][!][/] --ticket <ccache_file> required")
            return

        opts = {
            "RHOSTS": target_ip, "DOMAIN": domain,
            "TICKET_FILE": ticket, "LATERAL_METHOD": method or "auto",
        }

        console.print(f"\n[bold cyan][*][/] CCache-to-Shell — {target_ip}\n")
        result = cs_mod.run(options=opts, target=target_ip, mode="EXPLOIT")
        self._show_result(result)

    def do_secretsdump_bypass(self, arg):
        """Secretsdump with SPN validation bypass — work around Impacket bugs.

        Usage:
          secretsdump_bypass <target> -d domain --ticket <ccache> [--method auto|secretsdump_standard|secretsdump_vss|smbexec_reg]
          secretsdump_bypass <target> -d domain -u user -p pass
        """
        from armagedon.modules.exploits import exploit_secretsdump_bypass as sd_mod

        parts = arg.split()
        if not parts:
            console.print("[yellow]Usage: secretsdump_bypass <target> -d domain [options][/]")
            console.print("[dim]Options: --ticket CCACHE, -u USER -p PASS, --method METHOD, --mode EXPLOIT[/]")
            return

        target_ip = parts[0]
        user = passwd = domain = ticket = lm = nt = method = ""
        mode = "EXPLOIT"

        i = 1
        while i < len(parts):
            if parts[i] == "-u" and i + 1 < len(parts):
                user = parts[i + 1]; i += 2
            elif parts[i] == "-p" and i + 1 < len(parts):
                passwd = parts[i + 1]; i += 2
            elif parts[i] == "-d" and i + 1 < len(parts):
                domain = parts[i + 1]; i += 2
            elif parts[i] == "--ticket" and i + 1 < len(parts):
                ticket = parts[i + 1]; i += 2
            elif parts[i] == "--hash" and i + 1 < len(parts):
                nt = parts[i + 1]; i += 2
            elif parts[i] == "--lm" and i + 1 < len(parts):
                lm = parts[i + 1]; i += 2
            elif parts[i] == "--method" and i + 1 < len(parts):
                method = parts[i + 1]; i += 2
            elif parts[i] == "--mode" and i + 1 < len(parts):
                mode = parts[i + 1].upper(); i += 2
            else:
                i += 1

        opts = {
            "RHOSTS": target_ip, "DOMAIN": domain,
            "USERNAME": user, "PASSWORD": passwd,
            "HASH": nt, "LMHASH": lm,
            "TICKET_FILE": ticket,
            "METHOD": method or "auto",
        }

        console.print(f"\n[bold cyan][*][/] Secretsdump SPN Bypass — {target_ip}\n")
        result = sd_mod.run(options=opts, target=target_ip, mode=mode)
        self._show_result(result)

    do_info = lambda self, _: self._show_info()
    do_question_mark = do_help

    def run(self):
        console.print(BANNER)
        exploit_count = sum(1 for m in self.engine.modules if m["name"].startswith("exploits/"))
        console.print(f"[dim]Loaded {len(self.engine.modules)} modules | {exploit_count} exploits available[/]\n")

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
                    "ad_post_enum": self.do_ad_post_enum,
                    "bloodhound": self.do_bloodhound,
                    "domain": self.do_domain,
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
