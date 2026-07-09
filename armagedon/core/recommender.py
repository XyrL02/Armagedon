"""Exploit recommendation engine.
Takes a target fingerprint (scan results) and returns ranked exploit
candidates based on metadata matching."""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from armagedon.core.fingerprints import (
    SERVICE_VULN_MAP,
    PROTOCOL_VULN_MAP,
    EXPLOIT_METADATA,
    identify_os,
)

console = Console()


class Recommender:
    """Matches target scan data to available exploit modules."""

    def __init__(self, engine=None):
        self.engine = engine
        self._exploit_cache = None

    def _load_exploit_modules(self):
        """Discover available exploit modules via the engine."""
        if self.engine:
            available = self.engine.list_modules("exploits")
            return [m for m in available if m.get("category") == "exploits"] or available
        return []

    def _score_port_match(self, module_meta: dict, open_ports: list) -> int:
        """Score how well a module's required port matches the target."""
        required_port = module_meta.get("port")
        if required_port is None:
            return 0
        for sport, sinfo in SERVICE_VULN_MAP.items():
            if required_port == sport:
                return 5 if sport in open_ports else -10
        return 0 if required_port in open_ports else -5

    def _score_os_match(self, module_meta: dict, os_name: str) -> int:
        """Score OS compatibility."""
        target_os = os_name.lower() if os_name else ""
        compat = module_meta.get("os", [])
        if not compat:
            return 0
        for candidate in compat:
            if candidate.lower() in target_os or target_os in candidate.lower():
                return 3
        for candidate in compat:
            if "windows" in target_os and "windows" in candidate.lower():
                return 1
        return -2

    def recommend(
        self,
        target: str,
        scan_results: dict,
        top_n: int = 5,
    ) -> list:
        """Return ranked list of recommended exploit modules."""
        open_ports = scan_results.get("open_ports", [])
        os_name = scan_results.get("os", "")
        build = scan_results.get("build", 0)
        protocols = scan_results.get("protocols", {})
        hotfixes = scan_results.get("hotfixes", [])

        candidates = []

        for mod_name, meta in EXPLOIT_METADATA.items():
            score = 50

            port_score = self._score_port_match(meta, open_ports)
            score += port_score

            os_score = self._score_os_match(meta, os_name)
            score += os_score

            if meta.get("auth") is False:
                score += 10
            elif meta.get("auth") is True:
                score -= 2

            if meta.get("port") and meta["port"] in open_ports:
                score += 15

            score += meta.get("cvss", 0) * 2

            candidates.append({
                "module": mod_name,
                "cve": meta["cve"],
                "name": meta["name"],
                "cvss": meta["cvss"],
                "type": meta["type"],
                "auth": meta.get("auth", True),
                "port": meta.get("port"),
                "score": score,
                "description": meta.get("description", ""),
            })

        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates[:top_n]

    def display_recommendations(self, target: str, candidates: list):
        """Print recommendations as a rich table."""
        table = Table(title=f"\U0001f50d Exploit Recommendations for {target}")
        table.add_column("Score", style="cyan")
        table.add_column("CVE", style="yellow")
        table.add_column("Name", style="white")
        table.add_column("Type", style="magenta")
        table.add_column("CVSS", style="red")
        table.add_column("Auth", style="blue")

        for c in candidates:
            auth_str = "No" if not c["auth"] else "Yes"
            table.add_row(
                str(c["score"]),
                c["cve"],
                c["name"][:45],
                c["type"],
                f'{c["cvss"]:.1f}',
                auth_str,
            )

        console.print(table)
        return table

    def auto_recommend(
        self,
        target: str,
        scan_results: dict,
    ) -> list:
        """Full scan → recommend → interactive select → execute flow."""
        candidates = self.recommend(target, scan_results, top_n=8)
        self.display_recommendations(target, candidates)

        if not candidates:
            console.print("[yellow]No matching exploits found for this target.[/]")
            return []

        console.print("\n[bold]Select exploit to run[/] (number) or [bold]0[/] to cancel:")
        for i, c in enumerate(candidates, 1):
            console.print(f"  [{i}] {c['cve']} — {c['name'][:60]} (CVSS {c['cvss']:.1f})")

        try:
            choice = int(Prompt.ask("Choice", default="0"))
            if 1 <= choice <= len(candidates):
                selected = candidates[choice - 1]
                return [selected]
        except (ValueError, TypeError):
            pass

        console.print("[yellow]Canceled.[/]")
        return []
