# Armagedon

Advanced Windows Exploitation Framework

> *"Fall of the walled garden"*

Armagedon is a modular Windows exploitation framework featuring automated scan-to-exploit pipelines, exploit recommendation, and privilege escalation orchestration. Built for authorized penetration testing and security research.

## Features

- **Nexus Mode** -- Fully automated scan, recommend, exploit pipeline
- **Exploit Recommendation** -- Fingerprint-based matching of CVEs to target services
- **Privilege Escalation** -- Auto and interactive privesc orchestration
- **Post-Exploitation** -- Credential dumping, persistence, lateral movement, network discovery
- **Modular Architecture** -- Easy to add new exploit modules
- **SQLite Persistence** -- Tracks targets, sessions, loot, and findings
- **Interactive CLI** -- Tab completion, command history, rich terminal UI

## Modules

### Exploits

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `cve_2024_38077_madlicense_eop` | CVE-2024-38077 | 9.8 | Windows RDL Service Heap Overflow (pre-auth RCE to SYSTEM) |
| `cve_2024_43641_ffi_registry_eop` | CVE-2024-43641 | 7.8 | Windows Registry FFI EoP |
| `cve_2024_21338_appid_privesc` | CVE-2024-21338 | 7.8 | AppID Kernel Use-After-Free LPE — race on AppContainer node to SYSTEM |
| `cve_2024_26234_proxy_key_spoofing` | CVE-2024-26234 | 7.5 | Proxy Driver Key Spoofing — spoof TPM registry key to load attacker DLL |
| `cve_2024_26229_csc_privesc` | CVE-2024-26229 | 7.8 | CSC Service LPE — csc.sys offline cache UAF to SYSTEM |
| `cve_2025_21217_kernel_type_confusion` | CVE-2025-21217 | 7.8 | Kernel Type Confusion — IOCTL triggers object confusion for kernel r/w |
| `printnightmare_rce` | CVE-2021-1675 / CVE-2021-34527 | 9.8 | Print Spooler RCE/LPE — RpcAddPrinterDriverEx loads attacker DLL as SYSTEM |
| `zerologon` | CVE-2020-1472 | 10.0 | Netlogon Elevation — reset DC machine account password to null, impersonate DC |
| `samaccountname_spoof` | CVE-2021-42278 / CVE-2021-42287 | 8.1 | sAMAccountName Spoofing (NoPac) — impersonate DC via Kerberos name collision |
| `potato_attacks` | -- | -- | Hot/Rotten/Juicy/God Potato — SeImpersonatePrivilege abuse for SYSTEM |

### Scanners

| Module | Description |
|--------|-------------|
| `smb_scanner` | SMB service detection, OS fingerprinting, vulnerability signature matching |
| `vuln_scanner` | General vulnerability scanner |

### Privilege Escalation

| Module | Description |
|--------|-------------|
| `token_steal` | SeDebugPrivilege — steal SYSTEM token via process injection |
| `uac_bypass` | Fodhelper/ComputerDefaults auto-elevation bypass (UAC prompt bypass) |
| `service_privesc` | Unquoted service path exploitation for SYSTEM execution |
| `stored_creds` | Extract SAM hashes, LSA secrets, cached creds, WiFi passwords, config files |

### Post-Exploitation

| Module | Description |
|--------|-------------|
| `credential_dump` | Full credential extraction: SAM, LSA, NTDS.dit, cached domain creds |
| `persistence` | Install backdoors: scheduled tasks, registry run keys, new users, startup folder |
| `lateral_movement` | Pivot to other hosts via SMB, WMI, WinRM, PSExec |
| `network_discovery` | Enumerate internal network: interfaces, ARP, routes, DNS, ports, connections |

### Auxiliary / Recon

| Module | Description |
|--------|-------------|
| `smb_enum` | SMB enumeration (shares, users, groups) |
| `os_fingerprint` | OS fingerprinting |

## Installation

### Prerequisites

- Python 3.11+
- pip
- git
- impacket (recommended): `pip install impacket`

### From GitHub

```bash
git clone https://github.com/XyrL02/Armagedon.git
cd Armagedon
pip install .
```

### With all optional dependencies

```bash
pip install ".[full]"
```

### Upgrade

```bash
cd Armagedon && git pull && pip install --upgrade .
```

### Verify

```bash
armagedon --help
```

## Safety Mode

All exploit and privesc modules have a **SAFE_MODE** gate enabled by default. This prevents accidental damage to target systems.

```bash
# SAFE_MODE=1 (default) — blocks all destructive operations
armagedon --rhosts 10.10.10.1 --mode exploit  # BLOCKED

# SAFE_MODE=0 — allows exploit execution
export ARMAGEDON_SAFE_MODE=0
armagedon --rhosts 10.10.10.1 --mode exploit  # proceeds

# Re-enable safety
export ARMAGEDON_SAFE_MODE=1
```

**What SAFE_MODE blocks:**

| Risk Level | Modules | Blocked Operations |
|------------|---------|-------------------|
| CRITICAL | zerologon, madlicense, samaccountname_spoof | EXPLOIT (DC password reset, RCE, AD account modification) |
| HIGH | All kernel/service exploits, persistence | EXPLOIT + CRASH (driver loading, registry writes, user/task creation) |
| MEDIUM | privesc (token steal, UAC bypass, service privesc, potato) | EXPLOIT (process injection, registry writes, service restart) |
| LOW | credential_dump, lateral_movement, network_discovery | Not blocked (read-only enumeration) |

**CHECK mode always runs** (read-only, no modifications). Set `ARMAGEDON_SAFE_MODE=0` only when targeting isolated test/lab machines.

## Usage

### Interactive CLI

```bash
armagedon
```

### Nexus Mode (full auto pipeline)

```bash
# Auto: scan -> recommend -> exploit
armagedon --nexus 192.168.1.100

# Scan only
armagedon --nexus scan 192.168.1.100

# Scan + recommend (no exploit)
armagedon --nexus recommend 192.168.1.100

# Or via the interactive prompt:
# nexus <target>
# nexus scan <target>
# nexus recommend <target>
```

### Manual module usage

```bash
armagedon

# List modules
show modules

# Select and configure
use exploits/cve_2024_38077_madlicense_eop
set RHOSTS 192.168.1.100

# Check or exploit
set MODE CHECK
run
```

### Privilege Escalation

```bash
# Interactive privesc menu
armagedon --privesc

# Or from the interactive prompt:
privesc
privesc auto
```

### Post-Exploitation

```bash
# From interactive prompt:
use post/credential_dump
set RHOSTS 192.168.1.100
set SMB_USER admin
set SMB_PASS password123
run

use post/lateral_movement
set TARGET_HOSTS 192.168.1.101,192.168.1.102
run
```

### Quick scan

```bash
armagedon --scan 192.168.1.100:445,135,3389
```

### One-shot module

```bash
armagedon -t 192.168.1.100 -m exploits/cve_2024_38077_madlicense_eop
```

### Python module

```bash
python3 -m armagedon --help
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `show modules` | List all modules |
| `show options` | Show current module options |
| `use <module>` | Select a module |
| `set <opt> <val>` | Set a module option |
| `run` | Execute the current module |
| `check` | Check if target is vulnerable |
| `search <query>` | Search modules by name or CVE |
| `nexus <target>` | Full auto pipeline |
| `privesc` | Privilege escalation menu |
| `scan <target> [ports]` | Quick port scan |
| `loot` | Show collected loot/credentials |
| `sessions` | Show active sessions |
| `exit` | Exit Armagedon |

## Project Structure

```
armagedon/
  cli.py                      # Interactive CLI
  core/
    engine.py                 # Module loading and execution
    pipeline.py               # Nexus auto-exploit pipeline
    recommender.py            # Exploit recommendation engine
    fingerprints.py           # OS/service fingerprint database
    database.py               # SQLite persistence
    auto_privesc.py           # Privilege escalation orchestrator
  modules/
    exploits/                 # CVE exploit modules (10 modules)
    scanners/                 # Service scanners
    privesc/                  # Privilege escalation modules (4 modules)
    post/                     # Post-exploitation modules (4 modules)
    auxiliary/                # Auxiliary tools
    recon/                    # Reconnaissance modules
  pocs/                       # Standalone PoC binaries and source
```

## Module Options Reference

### Common Options (all modules)

| Option | Default | Description |
|--------|---------|-------------|
| `RHOSTS` | -- | Target IP address |
| `TIMEOUT` | 10 | Connection timeout in seconds |
| `PAYLOAD` | `cmd.exe /c whoami` | Command to execute on target |

### Credential Options (remote modules)

| Option | Default | Description |
|--------|---------|-------------|
| `SMB_USER` | -- | SMB/Domain username |
| `SMB_PASS` | -- | SMB/Domain password |
| `SMB_DOMAIN` | -- | NetBIOS domain name |

## Running Tests

```bash
python3 -m armagedon.tests.test_cve_2024_38077
```

## Disclaimer

For authorized security research and penetration testing only. Users are responsible for ensuring they have proper authorization before testing against any target.

## License

MIT
