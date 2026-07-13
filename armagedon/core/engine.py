"""
Armagedon Core Engine
Handles module loading, execution, and framework state.
"""
import json
import importlib
import logging
from pathlib import Path
from datetime import datetime

log = logging.getLogger("armagedon.core.engine")


class ArmagedonEngine:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.modules_dir = self.base_dir / "modules"
        self.current_target = None
        self.active_module = None
        self.modules = []
        self.output_dir = Path.home() / ".armagedon" / "output"
        self._ensure_init_files()
        self.discover_modules()

    def _ensure_init_files(self):
        for sub in ["", "scanners", "exploits", "post", "auxiliary", "privesc", "recon"]:
            init_path = self.modules_dir / sub / "__init__.py"
            if not init_path.exists():
                init_path.parent.mkdir(parents=True, exist_ok=True)
                init_path.write_text("# Package init\n")

    def discover_modules(self):
        self.modules = []
        module_types = ["scanners", "exploits", "post", "auxiliary", "privesc", "recon"]
        log.info("Discovering modules from %s", self.modules_dir)

        for mod_type in module_types:
            mod_path = self.modules_dir / mod_type
            if not mod_path.exists():
                continue

            for f in sorted(mod_path.glob("*.py")):
                if f.name == "__init__.py":
                    continue
                module_info = self._get_module_info(f)
                if module_info:
                    self.modules.append(module_info)

        log.info("Discovered %d modules", len(self.modules))
        return self.modules

    def _get_module_info(self, filepath):
        try:
            module_name = f"armagedon.modules.{filepath.parent.name}.{filepath.stem}"
            mod = importlib.import_module(module_name)

            info = {
                "name": f"{filepath.parent.name}/{filepath.stem}",
                "filepath": str(filepath),
                "path": filepath,
                "module": mod,
                "cve": getattr(mod, "CVE", "N/A"),
                "desc": getattr(mod, "DESCRIPTION", "No description"),
                "platform": getattr(mod, "PLATFORM", "Windows"),
                "rank": getattr(mod, "RANK", "normal"),
                "author": getattr(mod, "AUTHOR", "Unknown"),
                "disclosure": getattr(mod, "DISCLOSURE", "Unknown"),
                "type": filepath.parent.name,
                "options": getattr(mod, "OPTIONS", {}),
                "required": getattr(mod, "REQUIRED", {}),
                "descriptions": getattr(mod, "DESCRIPTIONS", {}),
            }
            log.debug("Loaded module: %s (%s)", info["name"], info["cve"])
            return info
        except Exception as e:
            log.error("Error loading module %s: %s", filepath.name, e)
            print(f"[!] Error loading module {filepath.name}: {e}")
            return None

    def list_modules(self, category: str = None) -> list:
        """Return modules filtered by category."""
        if not category:
            return self.modules
        return [m for m in self.modules if m.get("type") == category]

    def get_module_names(self) -> list:
        """Return sorted list of module names."""
        return sorted([m["name"] for m in self.modules])

    def search_modules(self, query):
        query = query.lower()
        results = []
        for m in self.modules:
            if query in m["name"].lower() or \
               query in (m.get("cve") or "").lower() or \
               query in (m.get("desc") or "").lower():
                results.append(m)
        return results

    def load_module(self, module_name):
        for m in self.modules:
            if m["name"] == module_name or m["name"].split("/")[-1] == module_name:
                self.active_module = m
                return True
        return False

    def set_module_option(self, option, value):
        if not self.active_module:
            return False
        if option in self.active_module.get("options", {}):
            self.active_module["options"][option] = value
            return True
        return False

    def set_target(self, target):
        self.current_target = target
        log.info("Target set: %s", target)
        if self.active_module:
            self.active_module["options"]["RHOSTS"] = target

    def run_module(self):
        if not self.active_module:
            return {"success": False, "error": "No module selected"}
        try:
            mod = self.active_module["module"]
            log.info("Running module: %s", self.active_module["name"])
            if hasattr(mod, "run"):
                if self.current_target:
                    mod.OPTIONS["RHOSTS"] = self.current_target
                result = mod.run(mod.OPTIONS)
                log.debug("Module %s finished", self.active_module["name"])
                return result
            else:
                log.warning("Module %s has no run() function", self.active_module["name"])
                return {"success": False, "error": "Module has no run() function"}
        except Exception as e:
            log.error("Module %s failed: %s", self.active_module["name"], e)
            import traceback
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

    def check_module(self):
        if not self.active_module:
            return False
        try:
            mod = self.active_module["module"]
            log.info("Checking module: %s", self.active_module["name"])
            if hasattr(mod, "check"):
                if self.current_target:
                    mod.OPTIONS["RHOSTS"] = self.current_target
                return mod.check(mod.OPTIONS)
            return None
        except Exception as e:
            log.error("Check failed for %s: %s", self.active_module["name"], e)
            print(f"[!] Check failed: {e}")
            return False

    def quick_scan(self, target, ports):
        results = []
        port_list = [p.strip() for p in ports.split(",")]
        log.info("Quick scan: %s ports=%s", target, ports)

        import socket
        for port in port_list:
            try:
                port = int(port)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self._guess_service(port)
                    banner = ""
                    try:
                        s.send(b"\r\n")
                        banner_data = s.recv(1024)
                        banner = banner_data.decode("utf-8", errors="ignore").strip()
                    except:
                        pass
                    results.append({
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner or service
                    })
                s.close()
            except:
                pass
        log.info("Quick scan found %d open ports", len(results))
        return results

    def _guess_service(self, port):
        services = {
            445: "SMB", 139: "NetBIOS", 3389: "RDP", 5985: "WinRM_HTTP",
            5986: "WinRM_HTTPS", 135: "RPC", 389: "LDAP", 636: "LDAPS",
            88: "Kerberos", 443: "HTTPS", 80: "HTTP", 53: "DNS",
            25: "SMTP", 1433: "MSSQL", 3306: "MySQL", 8080: "HTTP-Proxy",
            464: "Kerberos-Change", 3268: "GlobalCatalog", 3269: "GlobalCatalog_SSL",
            9389: "ADWS", 47001: "WinRM-PS", 5988: "WMI", 5989: "WMI-SSL"
        }
        return services.get(port, "unknown")
