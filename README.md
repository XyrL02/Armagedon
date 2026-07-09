# Armagedon

Advanced Windows Exploitation Framework.

> "Fall of the walled garden"

## Installation

### Prerequisites

- Python 3.8+
- pip
- git

### Option 1: From GitHub (Private Repo)

Since this repo is private, you need a **GitHub Personal Access Token**.

**Step 1 — Generate a PAT:**
1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Give it a name (e.g., "armagedon-install")
4. Set expiration as you prefer
5. Check the **`repo`** scope (full control of private repositories)
6. Click **Generate token** — copy the token (looks like `ghp_xxxxxxxxxxxxxxxxxxxx`)

**Step 2 — Install with your token:**
```bash
pip install git+https://YOUR_GITHUB_USERNAME:YOUR_PAT@github.com/XyrL02/Armagedon.git
```

Replace `YOUR_GITHUB_USERNAME` and `YOUR_PAT` with your values:

```bash
pip install git+https://XyrL02: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@github.com/XyrL02/Armagedon.git
```

> **Note:** When your PAT expires, generate a new one and replace the token in the command above.

### Option 2: Clone + Local Install (No Token Needed for Updates)

```bash
# Clone (one-time, requires token)
git clone https://YOUR_GITHUB_USERNAME:YOUR_PAT@github.com/XyrL02/Armagedon.git
cd Armagedon

# Install
pip install .

# Update later (no token needed — just pull)
git pull
```

### Option 3: SSH (Alternative — Requires SSH Key Setup)

```bash
# Add SSH key to GitHub first, then:
git clone git@github.com:XyrL02/Armagedon.git
cd Armagedon
pip install .
```

### Verify Installation

```bash
armagedon --help
```

You should see the Armagedon banner and usage information.

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
- `exploits/cve_2024_38077_madlicense_eop` — Windows Remote Desktop Licensing Service EoP (CVE-2024-38077)
- `exploits/cve_2024_43641_ffi_registry_eop` — Windows Registry FFI EoP (CVE-2024-43641)
- `auxiliary/smb_enum` — SMB enumeration

## License

For authorized security research and penetration testing only.
