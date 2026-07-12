# Armagedon

Advanced Windows Exploitation Framework

> *"Fall of the walled garden"*

Armagedon is a modular Windows exploitation framework featuring automated scan-to-exploit pipelines, exploit recommendation, and privilege escalation orchestration. Built for authorized penetration testing and security research.

## Features

- **Nexus Mode** -- Fully automated scan, recommend, exploit pipeline
- **Exploit Recommendation** -- Fingerprint-based matching of CVEs to target services
- **Privilege Escalation** -- Auto and interactive privesc orchestration
- **Modular Architecture** -- Easy to add new exploit modules
- **SQLite Persistence** -- Tracks targets, sessions, loot, and findings
- **Interactive CLI** -- Tab completion, command history, rich terminal UI

## Modules

| Category | Module | CVE | CVSS | Description |
|----------|--------|-----|------|-------------|
| Exploits | `cve_2024_38077_madlicense_eop` | CVE-2024-38077 | 9.8 | Windows RDL Service Heap Overflow (pre-auth RCE to SYSTEM) |
| Exploits | `cve_2024_43641_ffi_registry_eop` | CVE-2024-43641 | 7.8 | Windows Registry FFI EoP |
| Exploits | `cve_2024_21338_appid_privesc` | CVE-2024-21338 | 7.8 | AppID Kernel Use-After-Free LPE |
| Exploits | `cve_2024_26234_proxydriver_spoof` | CVE-2024-26234 | 7.5 | Proxy Driver Key Spoofing |
| Exploits | `cve_2024_26229_csc_lpe` | CVE-2024-26229 | 7.8 | CSC Service LPE |
| Exploits | `cve_2025_21217_win_kernel_lpe` | CVE-2025-21217 | 7.8 | Windows Kernel Type Confusion LPE |
| Scanners | `smb_scanner` | -- | -- | SMB service detection and fingerprinting |
| Scanners | `vuln_scanner` | -- | -- | Vulnerability scanner |
| Privesc | `token_steal` | -- | -- | SYSTEM token duplication from Winlogon/LSASS |
| Privesc | `uac_bypass` | -- | -- | UAC bypass via eventvwr / fodhelper |
| Privesc | `service_privesc` | -- | -- | Weak service permissions / unquoted path exploitation |
| Privesc | `stored_creds` | -- | -- | Saved credentials, vault, WLAN password extraction |
| Auxiliary | `smb_enum` | -- | -- | SMB enumeration |

## Installation

### Prerequisites

- Python 3.11+
- pip
- git

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
| `exit` | Exit Armagedon |

## Running Tests

```bash
python3 -m armagedon.tests.test_cve_2024_38077
```

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
    exploits/                 # CVE exploit modules
    scanners/                 # Service scanners
    privesc/                  # Privilege escalation modules
    auxiliary/                # Auxiliary tools
    recon/                    # Reconnaissance modules
  pocs/                       # Standalone PoC binaries and source
```

## Disclaimer

For authorized security research and penetration testing only. Users are responsible for ensuring they have proper authorization before testing against any target.

## License

MIT
