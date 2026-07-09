# Armagedon

Advanced Windows Exploitation Framework.

> "Fall of the walled garden"

## Installation

```bash
git clone https://github.com/your-org/armagedon
cd armagedon
pip install -r requirements.txt
pip install .
```

Or install directly from GitHub:

```bash
pip install git+https://github.com/your-org/armagedon.git
```

## Usage

```bash
# Interactive CLI
armagedon

# One-shot exploit
armagedon -t 192.168.1.100 -m exploits/cve_2024_38077_madlicense_eop

# Quick scan
armagedon --scan 192.168.1.100:445,135,3389
```

Or via Python module:

```bash
python3 -m armagedon
python3 -m armagedon --help
```

## Running Tests

```bash
python3 -m armagedon.tests.test_cve_2024_38077
```

## Modules

- `scanners/smb_scanner` — SMB service detection
- `scanners/vuln_scanner` — Vulnerability scanner
- `exploits/cve_2024_38077_madlicense_eop` — Windows Remote Desktop Licensing Service EoP
- `exploits/cve_2024_43641_ffi_registry_eop` — Windows Registry FFI EoP
- `auxiliary/smb_enum` — SMB enumeration
