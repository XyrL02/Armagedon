"""
Armagedon Core Engine
Handles module loading, execution, and framework state.
"""
import json
import importlib
from pathlib import Path
from datetime import datetime


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
        for sub in ["", "scanners", "exploits", "post", "auxiliary"]:
            init_path = self.modules_dir / sub / "__init__.py"
            if not init_path.exists():
                init_path.parent.mkdir(parents=True, exist_ok=True)
                init_path.write_text("# Package init\n")

    def discover_modules(self):
        self.modules = []
        module_types = ["scanners", "exploits", "post", "auxiliary"]

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
            return info
        except Exception as e:
            print(f"[!] Error loading module {filepath.name}: {e}")
            return None

    def search_modules(self, query):
        query = query.lower()
        results = []
        for m in self.modules:
            if query in m["name"].lower() or \
               query in m.get("cve", "").lower() or \
               query in m.get("desc", "").lower():
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
        if self.active_module:
            self.active_module["options"]["RHOSTS"] = target

    def run_module(self):
        if not self.active_module:
            return {"success": False, "error": "No module selected"}
        try:
            mod = self.active_module["module"]
            if hasattr(mod, "run"):
                if self.current_target:
                    mod.OPTIONS["RHOSTS"] = self.current_target
                result = mod.run(mod.OPTIONS)
                return result
            else:
                return {"success": False, "error": "Module has no run() function"}
        except Exception as e:
            import traceback
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

    def check_module(self):
        if not self.active_module:
            return False
        try:
            mod = self.active_module["module"]
            if hasattr(mod, "check"):
                if self.current_target:
                    mod.OPTIONS["RHOSTS"] = self.current_target
                return mod.check(mod.OPTIONS)
            return None
        except Exception as e:
            print(f"[!] Check failed: {e}")
            return False

    def quick_scan(self, target, ports):
        results = []
        port_list = [p.strip() for p in ports.split(",")]

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
