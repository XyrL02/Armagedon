# Armagedon

Advanced Windows Exploitation Framework.

> "Fall of the walled garden"

## Installation

### Prerequisites

- Python 3.8+
- pip
- git

### Option 1: From GitHub (Private Repo)

Since this repo is private, you need a **GitHub Personal Access Token (PAT)**
to install it. A PAT is like a password for your terminal to access GitHub.

---

#### How to create your Personal Access Token (step by step)

> If you already have a token, skip to Step 2.

| # | What to do | Where to click |
|---|------------|----------------|
| 1 | Log into your GitHub account at [github.com](https://github.com) | — |
| 2 | Click your **profile icon** (top-right corner) → **Settings** | `Settings` |
| 3 | Scroll down the left sidebar → click **Developer settings** (near the bottom) | `Developer settings` |
| 4 | Click **Personal access tokens** → **Tokens (classic)** | `Tokens (classic)` |
| 5 | Click **Generate new token (classic)** — you may be asked to re-enter your password | `Generate new token (classic)` |
| 6 | Under **Note**, type a name for this token (e.g., `armagedon-install`) — anything you'll recognize | `armagedon-install` |
| 7 | Under **Expiration**, choose when this token expires (e.g., `30 days`, `90 days`, or `No expiration`). Pick what works for you. | Your choice |
| 8 | Under **Select scopes**, scroll down and check the box for **`repo`** (it will auto-check all sub-scopes below it, giving full access to your private repos) | ☑ `repo` |
| 9 | Scroll to the bottom and click **Generate token** | `Generate token` |
| 10 | **IMPORTANT** — Copy the token **immediately**. It looks like `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx`. If you close this page, you can never see it again and must create a new one. | Copy it now |

✅ You now have your PAT. Keep it somewhere safe (like a password manager).

---

#### Step 2 — Install Armagedon

Now use your token in the install command:

```bash
pip install git+https://YOUR_GITHUB_USERNAME:YOUR_PAT@github.com/XyrL02/Armagedon.git
```

Replace two things:
- `YOUR_GITHUB_USERNAME` → your GitHub username (e.g., `john`)
- `YOUR_PAT` → the token you copied above (starts with `ghp_`)

**Example** (using the actual repo owner's token — yours will be different):

```bash
pip install git+https://XyrL02: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@github.com/XyrL02/Armagedon.git
```

---

#### ⚠️ When your token expires

GitHub tokens have an expiration date. When yours expires, you'll get an error:
```
fatal: authentication failed
```

**Don't worry** — just generate a new one:

1. Go back to https://github.com/settings/tokens
2. Delete the old expired token (click the trash icon)
3. Click **Generate new token (classic)** — same steps as above
4. Copy the new token and run the install command again with the new token

---

#### How to see how much time is left on your token

Go to https://github.com/settings/tokens — each token shows its expiration date
in the `Expires` column (e.g., `Jul 30, 2026` or `Never`).

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

#### How to update Armagedon (when a new version is released)

Same command as install, just add `--upgrade`:

```bash
pip install --upgrade git+https://YOUR_USERNAME:YOUR_NEW_TOKEN@github.com/XyrL02/Armagedon.git
```

> If your old PAT expired, generate a new one first (see steps above).

---

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
