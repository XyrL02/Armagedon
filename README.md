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
| `ad_post_enum` | Full AD post-exploitation enumeration: credential test, host enum, credential dump, LDAP enum, Kerberoast, hash crack, password spray |
| `credential_dump` | Full credential extraction: SAM, LSA, NTDS.dit, cached domain creds |
| `persistence` | Install backdoors: scheduled tasks, registry run keys, new users, startup folder |
| `lateral_movement` | Pivot to other hosts via SMB, WMI, WinRM, PSExec |
| `network_discovery` | Enumerate internal network: interfaces, ARP, routes, DNS, ports, connections |

### Auxiliary / Recon

| Module | Description |
|--------|-------------|
| `bloodhound_analyzer` | Load BloodHound JSON, find privilege escalation paths, auto-execute attack chains |
| `kerberos_attack` | ASREPROAST, KERBEROAST, Pass-the-Ticket, Golden/Silver Ticket |
| `password_spray` | Lockout-aware password spraying across Kerberos/NTLM services |
| `ldap_enum` | 12 LDAP enumeration categories: users, groups, delegation, LAPS, GMSA, etc. |
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
pip install -e .
```

> **Kali Linux / externally-managed Python (PEP 668)?** Use one of:
> ```bash
> # Option A — direct install (recommended for pentesting boxes)
> pip install -e . --break-system-packages
>
> # Option B — isolated virtual environment
> python3 -m venv venv
> source venv/bin/activate
> pip install -e .
> ```

### With all optional dependencies

```bash
pip install -e ".[full]"
# or on Kali:
pip install -e ".[full]" --break-system-packages
```

### Upgrade

```bash
cd Armagedon && git pull && pip install -e . --upgrade
# on Kali:
cd Armagedon && git pull && pip install -e . --upgrade --break-system-packages
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

### AD Post-Exploitation Enumeration

```bash
# Interactive prompt
ad_post_enum 10.10.10.1 -u admin -p Password1 -d CORP.LOCAL

# Full loop (default): test → enum → dump → ldap → kerb → crack → spray
ad_post_enum 10.10.10.1 -u admin -p Password1 -d CORP.LOCAL

# Run specific stages only
ad_post_enum 10.10.10.1 -u admin -p Password1 -d CORP.LOCAL --mode ENUM
ad_post_enum 10.10.10.1 -u admin -p Password1 -d CORP.LOCAL --mode DUMP
ad_post_enum 10.10.10.1 -u admin -p Password1 -d CORP.LOCAL --mode KERB

# Via module system
use post/ad_post_enum
set RHOSTS 10.10.10.1
set USERNAME admin
set PASSWORD Password1
set DOMAIN CORP.LOCAL
set MODE FULL
run
```

**What ad_post_enum does:**
1. Tests credentials on SMB, WinRM, RDP, LDAP (auto-fixes username formats)
2. Full host enumeration: systeminfo, users, groups, processes, network, sensitive files
3. Credential dumping: SAM, LSA, NTDS, LSASS via nxc
4. LDAP enumeration: LAPS, GMSA, delegation, Kerberoastable, AS-REP accounts
5. Kerberoasting + AS-REP roasting via impacket
6. Hash cracking with john
7. Password spraying discovered passwords across domain
8. Saves all results to a timestamped output directory

**Prerequisites:** `nxc` (NetExec), `john` (John the Ripper), `impacket` (GetUserSPNs, GetNPUsers)

### BloodHound Attack Path Analysis

```bash
# Analyze BloodHound data (find paths, no execution)
bloodhound ./loot/bloodhound

# Analyze from specific user
bloodhound ./loot/bloodhound --source visitor

# Analyze and auto-execute best paths
bloodhound ./loot/bloodhound --source visitor --mode exploit --auto-exec

# Limit depth and paths
bloodhound ./loot/bloodhound --max-depth 4 --max-paths 10

# Target specific SID
bloodhound ./loot/bloodhound --target S-1-5-21-...-512

# Via module system
use auxiliary/bloodhound_analyzer
set BLOODHOUND_DIR ./loot/bloodhound
set SOURCE_USER visitor
set MODE EXPLOIT
set AUTO_EXEC true
run
```

**What bloodhound does:**
1. Loads SharpHound/BloodHound JSON files (users.json, groups.json, computers.json, ACLs, sessions)
2. Builds a relationship graph of all AD objects and their edges
3. Identifies 10 types of privilege escalation paths:
   - **GROUP_MEMBERSHIP** — MemberOf chain to Domain Admins
   - **ADMIN_ACCESS** — AdminTo on computer → DA
   - **SESSION_HIJACK** — HasSession → AdminTo on DA
   - **DELEGATION_ABUSE** — AllowedToDelegate (unconstrained/constrained)
   - **RBCD_ABUSE** — GenericAll/WriteOwner/WriteDACL → RBCD
   - **ACL_ABUSE** — GenericAll/WriteDACL on user/group → DA
   - **PASSWORD_RESET** — ForceChangePassword on DA user
   - **ACL_CHAIN** — WriteDACL → AddMember → DA
   - **SID_HISTORY** — HasSIDHistory abuse
   - **DCOM_ABUSE** — ExecuteDCOM on computer
4. Ranks paths by severity (critical > high > medium) and effort (low > medium > high)
5. Auto-executes the most promising paths using existing Armagedon modules
6. Exports all paths to JSON for reporting

**Modes:**
- `CHECK` — verify files load, show summary
- `ANALYZE` — find and display paths (no execution)
- `EXPLOIT` — find paths + auto-execute promising ones (requires `--auto-exec`)

**BloodHound input:** Place SharpHound collection output (JSON files) in a directory, or point to a single JSON file.

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

### Core

| Command | Args | Description |
|---------|------|-------------|
| `help` | — | Show help panel |
| `?` | — | Alias for `help` |
| `exit` | — | Exit Armagedon |
| `quit` | — | Alias for `exit` |
| `back` | — | Deselect current module, return to main menu |

### Target & Module

| Command | Args | Description |
|---------|------|-------------|
| `target` | `<ip>` | Set target IP (same as `set RHOSTS <ip>`) |
| `show` | `modules` | List all 27 modules with name, CVE, rank, description |
| `show` | `options` | Show options for the currently selected module |
| `show` | `info` | Show detailed info for the currently selected module |
| `modules` | — | Alias for `show modules` |
| `options` | — | Alias for `show options` |
| `use` | `<module>` | Select a module (e.g. `use exploits/zerologon`) |
| `set` | `<opt> <val>` | Set a module option (e.g. `set RHOSTS 10.10.10.1`) |
| `run` | — | Execute the currently selected module |
| `check` | — | Run the module in CHECK mode (read-only, no changes) |
| `search` | `<query>` | Search modules by name or CVE keyword |
| `info` | — | Alias for `show info` |

### Nexus (Auto-Exploit Pipeline)

| Command | Args | Description |
|---------|------|-------------|
| `nexus` | `<target>` | Full auto: scan → fingerprint → recommend → exploit |
| `nexus` | `scan <target>` | Scan only (enumerate services, no exploit) |
| `nexus` | `recommend <target>` | Scan + recommend exploits (no execution) |

### Privilege Escalation

| Command | Args | Description |
|---------|------|-------------|
| `privesc` | — | Interactive module picker (choose from 4 modules) |
| `privesc` | `auto` | Auto-detect privilege level + try all modules low→high risk |
| `privesc` | `auto -u <user> -p <pass> -d <domain>` | Auto with remote privilege detection via nxc |
| `privesc` | `bh <dir> [--source SID] [-u user] [-p pass] [-d domain]` | BloodHound-driven escalation chain |

**`privesc auto` flags:**
| Flag | Required | Description |
|------|----------|-------------|
| `-u` | No | Username for remote privilege detection |
| `-p` | No | Password for remote privilege detection |
| `-d` | No | Domain for remote privilege detection |

**`privesc bh` flags:**
| Flag | Required | Description |
|------|----------|-------------|
| `<dir>` | Yes | Directory containing BloodHound JSON files |
| `--source` | No | SID or name of the source account to escalate from |
| `-u` | No | Username for module execution |
| `-p` | No | Password for module execution |
| `-d` | No | Domain for module execution |

### AD Post-Exploitation Enumeration

| Command | Args | Description |
|---------|------|-------------|
| `ad_post_enum` | `<target> -u <user> -p <pass> -d <domain>` | Full 8-stage AD post-exploitation loop |
| `ad_post_enum` | `<target> -u <user> -p <pass> -d <domain> --mode <mode>` | Run specific stages only |

**`ad_post_enum` flags:**
| Flag | Required | Description |
|------|----------|-------------|
| `<target>` | Yes | Target IP address |
| `-u` | Yes | Username |
| `-p` | Yes | Password |
| `-d` | Yes | Domain (e.g. `CORP.LOCAL`) |
| `--mode` | No | `FULL` (default), `ENUM`, `DUMP`, `KERB`, `CRACK`, `SPRAY` |

**`ad_post_enum` stages (in FULL mode):**
1. `TEST` — Credential validation across SMB/WinRM/RDP/LDAP
2. `ENUM` — Host enumeration (systeminfo, users, groups, processes, network, files)
3. `DUMP` — Credential dumping (SAM, LSA, NTDS, LSASS via nxc)
4. `LDAP` — LDAP enumeration (LAPS, GMSA, delegation, Kerberoastable, AS-REP)
5. `KERB` — Kerberoasting + AS-REP roasting via impacket
6. `CRACK` — Hash cracking with john
7. `SPRAY` — Password spraying discovered passwords across domain

### BloodHound Attack Path Analysis

| Command | Args | Description |
|---------|------|-------------|
| `bloodhound` | `<dir_or_file>` | Load + summarize BloodHound data |
| `bloodhound` | `<dir_or_file> --mode analyze` | Find privilege escalation paths (no execution) |
| `bloodhound` | `<dir_or_file> --mode exploit --auto-exec` | Find paths + auto-execute best ones |
| `bloodhound` | `<dir_or_file> --source <user>` | Analyze from a specific source account |
| `bloodhound` | `<dir_or_file> --target <SID>` | Target a specific SID |

**`bloodhound` flags:**
| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `<dir_or_file>` | Yes | — | Directory of SharpHound JSON files or single JSON file |
| `--source` | No | auto | Source user SID or name to analyze escalation from |
| `--target` | No | — | Target SID to find paths to |
| `--mode` | No | `ANALYZE` | `CHECK`, `ANALYZE`, or `EXPLOIT` |
| `--auto-exec` | No | off | Auto-execute best attack paths (only with `--mode exploit`) |
| `--max-depth` | No | `6` | Maximum graph traversal depth |
| `--max-paths` | No | `20` | Maximum number of paths to report |

**`bloodhound` modes:**
| Mode | Description |
|------|-------------|
| `CHECK` | Verify JSON files load correctly, show summary |
| `ANALYZE` | Find and display all privilege escalation paths (no execution) |
| `EXPLOIT` | Find paths + auto-execute the most promising ones using Armagedon modules |

### Scan

| Command | Args | Description |
|---------|------|-------------|
| `scan` | `<target> [ports]` | Quick nmap port scan (default ports: 445,139,3389,5985,5986,135,389,636,88,443,80) |

### Module Execution

| Command | Args | Description |
|---------|------|-------------|
| `use` | `<category/module>` | Select module (e.g. `use exploits/zerologon`, `use privesc/token_steal`) |
| `set` | `RHOSTS <ip>` | Set target IP for current module |
| `set` | `MODE CHECK` | Set module to check-only mode |
| `set` | `MODE EXPLOIT` | Set module to exploit mode (requires `SAFE_MODE=0`) |
| `set` | `SMB_USER <user>` | Set SMB/WinRM username |
| `set` | `SMB_PASS <pass>` | Set SMB/WinRM password |
| `set` | `SMB_DOMAIN <domain>` | Set domain name |
| `run` | — | Execute current module with configured options |
| `check` | — | Run current module in CHECK mode (safe, read-only) |

### Module Options Reference

**Common options (all modules):**
| Option | Default | Description |
|--------|---------|-------------|
| `RHOSTS` | — | Target IP address |
| `TIMEOUT` | `10` | Connection timeout in seconds |
| `PAYLOAD` | `cmd.exe /c whoami` | Command to execute on target |
| `MODE` | `CHECK` | `CHECK` (safe) or `EXPLOIT` (requires `ARMAGEDON_SAFE_MODE=0`) |

**Credential options (remote modules):**
| Option | Default | Description |
|--------|---------|-------------|
| `SMB_USER` | — | SMB/Domain username |
| `SMB_PASS` | — | SMB/Domain password |
| `SMB_DOMAIN` | — | NetBIOS domain name |

**BloodHound module options:**
| Option | Default | Description |
|--------|---------|-------------|
| `BLOODHOUND_DIR` | — | Directory containing SharpHound JSON output |
| `BLOODHOUND_FILE` | — | Single BloodHound JSON file |
| `SOURCE_USER` | auto | Source account SID or name |
| `TARGET_SID` | — | Target SID to find paths to |
| `MAX_DEPTH` | `6` | Max traversal depth |
| `MAX_PATHS` | `20` | Max paths to report |
| `AUTO_EXEC` | `false` | Auto-execute attack paths |
| `AUTO_EXEC_LIMIT` | `5` | Max auto-executed paths |

**AD Post-Enum module options:**
| Option | Default | Description |
|--------|---------|-------------|
| `USERNAME` | — | Authentication username |
| `PASSWORD` | — | Authentication password |
| `DOMAIN` | — | AD domain name |
| `MODE` | `FULL` | `FULL`, `ENUM`, `DUMP`, `KERB`, `CRACK`, `SPRAY` |
| `STEPS` | `TEST,ENUM,DUMP,LDAP,KERB,CRACK,SPRAY` | Comma-separated stages to run |

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
    bloodhound.py             # BloodHound attack path analyzer
  modules/
    exploits/                 # CVE exploit modules (10 modules)
    scanners/                 # Service scanners
    privesc/                  # Privilege escalation modules (4 modules)
    post/                     # Post-exploitation modules (5 modules)
    auxiliary/                # Auxiliary tools (5 modules)
    recon/                    # Reconnaissance modules
  pocs/                       # Standalone PoC binaries and source
```

## Running Tests

```bash
python3 -m armagedon.tests.test_cve_2024_38077
```

## Disclaimer

For authorized security research and penetration testing only. Users are responsible for ensuring they have proper authorization before testing against any target.

## License

MIT
