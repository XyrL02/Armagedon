"""
Armagedon Mock RPC Server — DCE/RPC test harness for CVE-2024-38077
Simulates the TSLSP (3d267954-eeb7-11d1-b94e-00c04fa3080d) RPC endpoint
over ncacn_ip_tcp so the exploit module can be tested without a real target.

Supports:
  - RPC Bind / Bind Ack (UUID matching)
  - Opnum 1 (TLSRpcConnect) — returns a fake context handle
  - Opnum 49 (TLSRpcTelephoneRegisterLKP) — logs and validates the overflow data
  - Request / Response / Fault PDU handling
"""

import os
import sys
import json
import struct
import socket
import threading
import base64
import time
from pathlib import Path

# ─── DCE/RPC Constants ───────────────────────────────────────────────────────
RPC_VER = 5
RPC_VER_MINOR = 0

# PDU types
PDU_REQUEST = 0x00
PDU_PING = 0x01
PDU_RESPONSE = 0x02
PDU_FAULT = 0x03
PDU_BIND = 0x0B
PDU_BIND_ACK = 0x0C
PDU_BIND_NACK = 0x0D
PDU_ALTER_CONTEXT = 0x0E

# PFC flags
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_DID_NOT_EXECUTE = 0x10

# Data representation (little-endian, ASCII, IEEE)
DREP = b'\x10\x00\x00\x00'

# Standard NDR transfer syntax
NDR_UUID = b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'
NDR_VERSION = struct.pack("<II", 2, 0)

# TSLSP UUID
TSLSP_UUID_BYTES = bytes.fromhex(
    "54 79 26 3d b7 ee d1 11 b9 4e 00 c0 4f a3 08 0d".replace(" ", "")
)
TSLSP_UUID_STR = "3d267954-eeb7-11d1-b94e-00c04fa3080d"


# ─── DCE/RPC PDU Builder ─────────────────────────────────────────────────────
def build_pdu_header(ptype, frag_length, call_id, flags=PFC_FIRST_FRAG | PFC_LAST_FRAG):
    """Build a 16-byte DCE/RPC common header (little-endian)."""
    return struct.pack(
        "<BBBB4sHHl",
        RPC_VER,           # rpc_vers
        RPC_VER_MINOR,     # rpc_vers_minor
        ptype,             # ptype
        flags,             # pfc_flags
        DREP,              # packed_drep (4 bytes)
        frag_length,       # frag_length
        0,                 # auth_length
        call_id,           # call_id
    )


def build_bind_ack(call_id, assoc_group_id=0x539):
    """
    Build a Bind Ack PDU accepting the presentation context.
    Result[0]: acceptance (0) with NDR transfer syntax.
    """
    sec_addr = b'\x00\x00'  # no secondary address
    body = struct.pack("<HH", 0x7FFF, 0x7FFF)  # MaxXmitFrag, MaxRecvFrag (large to avoid frag)
    body += struct.pack("<I", assoc_group_id)  # AssocGroupId
    body += struct.pack("<H", len(sec_addr))    # SecAddr length
    body += sec_addr
    body += struct.pack("<H", 1)   # NumResults

    # Result[0]: acceptance (0), reason (0), NDR syntax
    body += struct.pack("<HH", 0, 0)  # Result, Reason
    body += NDR_UUID                  # TransferSyntax UUID (NDR)
    body += NDR_VERSION               # TransferSyntax version

    frag_len = 16 + len(body)
    header = build_pdu_header(PDU_BIND_ACK, frag_len, call_id)
    return header + body


def build_bind_nack(call_id, reason=0):
    """Build a Bind Nack PDU."""
    body = struct.pack("<H", reason)  # ProviderRejectReason
    # Authn protocol (optional)
    frag_len = 16 + len(body)
    header = build_pdu_header(PDU_BIND_NACK, frag_len, call_id)
    return header + body


def build_response(call_id, stub_data):
    """Build a Response PDU with given stub data."""
    cancel_count = 0
    # Response header: AllocHint(4) + ContextId(2) + CancelCount(1) = 7 bytes
    body = struct.pack("<IHB", 0, 0, cancel_count)
    # Add alignment padding so stub data starts at 8-byte aligned offset from PDU start
    # After 16-byte header + 7 bytes body header, we need 1 more byte to reach offset 24
    body += b'\x00'  # alignment padding to 8-byte boundary
    body += stub_data
    frag_len = 16 + len(body)
    header = build_pdu_header(PDU_RESPONSE, frag_len, call_id)
    return header + body


def build_fault(call_id, status=0x1C010001):
    """Build a Fault PDU (default: rpc_s_access_denied)."""
    cancel_count = 0
    body = struct.pack("<IHBI", 0, 0, cancel_count, status)
    frag_len = 16 + len(body)
    flags = PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_DID_NOT_EXECUTE
    header = build_pdu_header(PDU_FAULT, frag_len, call_id, flags=flags)
    return header + body


# ─── NDR Stub Builder ─────────────────────────────────────────────────────────
def build_context_handle(data=b'\x41' * 20):
    """Build a 20-byte NDR context handle."""
    return data.ljust(20, b'\x00')[:20]


# ─── DCE/RPC PDU Parser ──────────────────────────────────────────────────────

class RpcPdu:
    """Parsed DCE/RPC PDU with header and body access."""

    def __init__(self, data):
        self.raw = data
        if len(data) < 16:
            raise ValueError("PDU too short")
        self.header = data[:16]
        self.body = data[16:]
        self._parse_header()

    def _parse_header(self):
        (self.rpc_vers, self.rpc_vers_minor, self.ptype, self.pfc_flags,
         self.drep_bytes, self.frag_length, self.auth_length, self.call_id) = \
            struct.unpack_from("<BBBB4sHHl", self.header)

    @property
    def has_auth(self):
        return self.auth_length > 0

    @property
    def is_last_frag(self):
        return bool(self.pfc_flags & PFC_LAST_FRAG)

    @property
    def is_first_frag(self):
        return bool(self.pfc_flags & PFC_FIRST_FRAG)

    def body_without_auth(self):
        """Return PDU body excluding the auth verifier trailer."""
        if self.has_auth:
            return self.body[:-self.auth_length]
        return self.body

    def __repr__(self):
        ptype_names = {
            PDU_REQUEST: "REQUEST",
            PDU_RESPONSE: "RESPONSE",
            PDU_FAULT: "FAULT",
            PDU_BIND: "BIND",
            PDU_BIND_ACK: "BIND_ACK",
            PDU_BIND_NACK: "BIND_NACK",
            PDU_ALTER_CONTEXT: "ALTER_CONTEXT",
        }
        return (
            f"RpcPdu(ptype={ptype_names.get(self.ptype, hex(self.ptype))}, "
            f"call_id={self.call_id}, "
            f"frag_len={self.frag_length}, "
            f"body_len={len(self.body)}, "
            f"auth={self.auth_length})"
        )


class BindPdu(RpcPdu):
    """Parsed Bind PDU with context items."""

    def __init__(self, data):
        super().__init__(data)
        self.contexts = []
        self._parse_body()

    def _parse_body(self):
        body = self.body_without_auth()
        offset = 0
        self.max_xmit_frag = struct.unpack_from("<H", body, offset)[0]
        offset += 2
        self.max_recv_frag = struct.unpack_from("<H", body, offset)[0]
        offset += 2
        self.assoc_group_id = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        num_ctx = struct.unpack_from("<I", body, offset)[0]
        offset += 4

        for _ in range(num_ctx):
            ctx_id = struct.unpack_from("<H", body, offset)[0]
            offset += 2
            num_trans = body[offset]
            offset += 1

            # Interface UUID (16 bytes)
            iface_uuid = body[offset:offset + 16]
            offset += 16
            iface_ver_major = struct.unpack_from("<H", body, offset)[0]
            offset += 2
            iface_ver_minor = struct.unpack_from("<H", body, offset)[0]
            offset += 2

            self.contexts.append({
                "ctx_id": ctx_id,
                "iface_uuid": iface_uuid,
                "iface_uuid_hex": iface_uuid.hex(),
                "iface_ver_major": iface_ver_major,
                "iface_ver_minor": iface_ver_minor,
            })


class RequestPdu(RpcPdu):
    """Parsed Request PDU with opnum."""

    def __init__(self, data):
        super().__init__(data)
        self._parse_body()

    def _parse_body(self):
        body = self.body_without_auth()
        self.alloc_hint = struct.unpack_from("<I", body, 0)[0]
        self.context_id = struct.unpack_from("<H", body, 4)[0]
        self.opnum = struct.unpack_from("<H", body, 6)[0]
        self.stub_data = body[8:]
        # Handle padded alignment (stub data starts at 8-byte aligned offset)
        # but for our structures it's fine


# ─── Mock TSLSP Server ───────────────────────────────────────────────────────

class MockTSLSPServer:
    """
    TCP-based DCE/RPC mock server that simulates the Windows Remote Desktop
    Licensing Service (TSLSP) RPC endpoint.

    Usage:
        server = MockTSLSPServer(port=24444)
        server.start()  # Non-blocking (daemon thread)
        ...
        server.stop()
    """

    def __init__(self, port=24444, verbose=True):
        self.port = port
        self.verbose = verbose
        self.server_sock = None
        self.running = False
        self._thread = None

        # Callback tracking
        self.bind_count = 0
        self.connect_count = 0
        self.telephone_count = 0
        self.last_request_data = None
        self.last_request_stub = None
        self.all_requests = []

        # Simulated heap size (for overflow verification)
        self.overflow_config = {
            "vulnerable": True,
            "bug_mul_div": True,  # (N/4)*3 bug is enabled
        }

    def log(self, msg, *args):
        if self.verbose:
            if args:
                msg = msg % args
            print(f"  [MOCK: {self.port}] {msg}")

    # ─── Server Lifecycle ────────────────────────────────────────────────

    def start(self):
        """Start the mock server in a daemon thread."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", self.port))
        self.server_sock.listen(5)
        self.server_sock.settimeout(1.0)
        self.running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.name = f"MockRPC-{self.port}"
        self._thread.start()
        self.log("Mock TSLSP server listening on 127.0.0.1:%d", self.port)
        return self

    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        self.log("Mock server stopped")

    def is_running(self):
        return self.running

    def reset_counters(self):
        """Reset all request counters."""
        self.bind_count = 0
        self.connect_count = 0
        self.telephone_count = 0
        self.last_request_data = None
        self.last_request_stub = None
        self.all_requests = []

    def get_stats(self):
        return {
            "bind_count": self.bind_count,
            "connect_count": self.connect_count,
            "telephone_count": self.telephone_count,
            "total_requests": len(self.all_requests),
        }

    # ─── Connection Handling ─────────────────────────────────────────────

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
                self.log("Connection from %s:%d", *addr)
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log("Accept error: %s", e)

    def _handle_client(self, sock, addr):
        try:
            sock.settimeout(10)
            # Per-client fragment buffer for multi-fragment requests
            frag_buf = {}
            self._rpc_loop(sock, addr, frag_buf)
        except Exception as e:
            self.log("Client %s error: %s", addr[0], e)
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self.log("Client %s disconnected", addr[0])

    def _rpc_loop(self, sock, addr, frag_buf):
        """Main RPC loop — reads PDUs and dispatches to handlers.
        Handles TCP-level fragmentation (recv may return partial PDUs)."""
        recv_buf = b''
        while self.running:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            except Exception:
                break

            if not chunk:
                break

            recv_buf += chunk

            # Process all complete PDUs in the buffer
            while len(recv_buf) >= 16:
                pdu_len = struct.unpack_from("<H", recv_buf, 8)[0]  # frag_length
                if len(recv_buf) < pdu_len:
                    break  # incomplete PDU, wait for more data

                pdu_data = recv_buf[:pdu_len]
                recv_buf = recv_buf[pdu_len:]

                try:
                    pdu = RpcPdu(pdu_data)
                except ValueError as e:
                    self.log("Bad PDU: %s", e)
                    continue

                self.log("Received: %s (len=%d)", pdu, len(pdu_data))

                if pdu.ptype == PDU_BIND or pdu.ptype == PDU_ALTER_CONTEXT:
                    response = self._handle_bind(pdu_data)
                    if response:
                        sock.sendall(response)
                        self.log("Sent response (%d bytes)", len(response))
                elif pdu.ptype == PDU_REQUEST:
                    self._handle_request_frag(pdu_data, frag_buf, sock)
                elif pdu.ptype == PDU_PING:
                    continue
                else:
                    self.log("Unhandled PDU type: %d", pdu.ptype)
                    response = build_fault(pdu.call_id, 0x1C000001)
                    if response:
                        sock.sendall(response)
                        self.log("Sent response (%d bytes)", len(response))

    # ─── Bind Handler ───────────────────────────────────────────────────

    def _handle_bind(self, data):
        """Handle Bind PDU — validate interface UUID and respond."""
        try:
            bind = BindPdu(data)
        except Exception as e:
            self.log("Failed to parse bind: %s", e)
            return build_bind_nack(struct.unpack_from("<l", data[12:16])[0])

        self.bind_count += 1

        if not bind.contexts:
            self.log("No context items in bind")
            return build_bind_nack(bind.call_id, 2)

        ctx = bind.contexts[0]
        iface_hex = ctx["iface_uuid_hex"]

        # Check if this matches the TSLSP UUID
        matching = iface_hex == TSLSP_UUID_BYTES.hex()
        if matching:
            self.log("TSLSP UUID MATCH: %s", iface_hex[:32])
        else:
            self.log("Unknown UUID: %s", iface_hex[:32])

        ctx_version = f"{ctx['iface_ver_major']}.{ctx['iface_ver_minor']}"
        self.log("Interface version: %s", ctx_version)

        # Accept the bind — always accept any UUID for testing
        self.log("Accepting bind with NDR transfer syntax")
        return build_bind_ack(bind.call_id)

    # ─── Request Handler (multi-fragment) ──────────────────────────────

    class _MockReq:
        """Minimal request-like object for assembled fragments."""
        def __init__(self, stub_data, opnum, call_id):
            self.stub_data = stub_data
            self.opnum = opnum
            self.call_id = call_id

    def _handle_request_frag(self, data, frag_buf, sock):
        """Handle request PDU, supporting multi-fragment assembly."""
        try:
            pdu = RpcPdu(data)
        except Exception:
            call_id = struct.unpack_from("<l", data[12:16])[0]
            resp = build_fault(call_id)
            sock.sendall(resp)
            return

        call_id = pdu.call_id
        body = pdu.body_without_auth()
        context_id = struct.unpack_from("<H", body, 4)[0]
        opnum = struct.unpack_from("<H", body, 6)[0]
        stub_data = body[8:]

        is_first = pdu.is_first_frag
        is_last = pdu.is_last_frag

        if is_first:
            frag_buf[call_id] = {
                'opnum': opnum, 'context_id': context_id, 'stubs': [],
            }
            self.log("Request frag[first]: opnum=%d, call_id=%d, stub=%d",
                     opnum, call_id, len(stub_data))

        if call_id in frag_buf:
            frag_buf[call_id]['stubs'].append(stub_data)
            if not is_first:
                self.log("Request frag[cont]: opnum=%d, call_id=%d, stub=%d",
                         opnum, call_id, len(stub_data))

        if not is_last:
            return  # more fragments pending

        if call_id in frag_buf:
            entry = frag_buf.pop(call_id)
            full_stub = b''.join(entry['stubs'])
            self.log("Request complete: opnum=%d, call_id=%d, stub=%d bytes",
                     entry['opnum'], call_id, len(full_stub))
            self.all_requests.append({
                "opnum": entry['opnum'],
                "call_id": call_id,
                "stub_len": len(full_stub),
                "stub_hex": full_stub[:100].hex(),
            })
            mock = self._MockReq(full_stub, entry['opnum'], call_id)
            if entry['opnum'] == 1:
                response = self._handle_opnum1(mock)
            elif entry['opnum'] == 49:
                response = self._handle_opnum49(mock)
            else:
                self.log("Unsupported opnum %d", entry['opnum'])
                response = build_fault(call_id, 0x1C000002)
        else:
            # No fragment buffer (shouldn't happen if first frag set it up)
            self.log("No fragment state for call_id=%d, dispatching raw", call_id)
            req_pdu = RequestPdu(data)
            response = self._handle_request(req_pdu)

        if response:
            sock.sendall(response)
            self.log("Sent response (%d bytes)", len(response))

    def _handle_request(self, data):
        """Handle Request PDU — dispatch by opnum."""
        try:
            req = RequestPdu(data)
        except Exception as e:
            self.log("Failed to parse request: %s", e)
            call_id = struct.unpack_from("<l", data[12:16])[0]
            return build_fault(call_id)

        self.log("Request: opnum=%d, call_id=%d, stub_len=%d",
                 req.opnum, req.call_id, len(req.stub_data))

        self.all_requests.append({
            "opnum": req.opnum,
            "call_id": req.call_id,
            "stub_len": len(req.stub_data),
            "stub_hex": req.stub_data[:100].hex(),
        })

        if req.opnum == 1:
            return self._handle_opnum1(req)
        elif req.opnum == 49:
            return self._handle_opnum49(req)
        else:
            self.log("Unsupported opnum %d", req.opnum)
            return build_fault(req.call_id, 0x1C000002)

    def _handle_opnum1(self, req):
        """TLSRpcConnect (opnum 1): return a fake context handle."""
        self.connect_count += 1
        self.log("TLSRpcConnect (call #%d): returning context handle", self.connect_count)

        # Build a 20-byte context handle
        ch = build_context_handle(b'\xBE\xEF\xCA\xFE' + b'\x00' * 16)
        self.log("Context handle: %s (%d bytes)", ch.hex()[:40], len(ch))
        return build_response(req.call_id, ch)

    def _handle_opnum49(self, req):
        """TLSRpcTelephoneRegisterLKP (opnum 49): validate overflow data."""
        self.telephone_count += 1
        stub = req.stub_data
        self.log("TLSRpcTelephoneRegisterLKP: stub=%d bytes", len(stub))

        # Parse the stub body:
        #   [20 bytes context handle]
        #   [4 bytes ULONG cbData]
        #   [4 bytes ULONG MaxCount for conformant array]
        #   [cbData bytes of pbData (the encoded base64 payload)]
        offset = 0
        ctx_handle = stub[offset:offset + 20]
        offset += 20
        self.log("  Context handle from client: %s", ctx_handle.hex()[:40])

        # cbData
        cb_data = struct.unpack_from("<I", stub, offset)[0]
        offset += 4
        self.log("  cbData ULONG: %d (0x%x)", cb_data, cb_data)

        # Conformant array: MaxCount (ULONG) then data
        if offset + 4 <= len(stub):
            array_max = struct.unpack_from("<I", stub, offset)[0]
            offset += 4
            self.log("  Array MaxCount: %d", array_max)

        # The actual data
        remaining = len(stub) - offset
        self.log("  Remaining data bytes: %d", remaining)

        if remaining > 0:
            raw_wire_data = stub[offset:offset + remaining]
            self.last_request_data = raw_wire_data
            self.last_request_stub = raw_wire_data

            # Try to decode as base64
            try:
                decoded = base64.b64decode(raw_wire_data)
                self.log("  Base64 decode: %d -> %d bytes", len(raw_wire_data), len(decoded))
                self.log("  Decoded prefix: %s", decoded[:64].hex())

                # Validate overflow math (simulate the bug)
                self._validate_overflow(raw_wire_data, decoded)

            except Exception:
                self.log("  Not valid base64 (or truncated): %s", raw_wire_data[:64].hex())

        # Return success (DWORD = 0)
        return_stub = struct.pack("<I", 0)
        self.log("  Returning: dwErrCode=0 (success)")
        self.last_request_data = stub
        return build_response(req.call_id, return_stub)

    def _validate_overflow(self, encoded_data, raw_payload):
        """Simulate the CDataCoding::DecodeData buffer miscalculation."""
        encoded_len = len(encoded_data)
        alloc_size = (encoded_len // 4) * 3           # Bug: what server allocates
        correct_size = ((encoded_len + 3) // 4) * 3    # Fix: what server should allocate
        raw_size = len(raw_payload)
        overflow = raw_size - alloc_size

        self.log("")
        self.log("  === OVERFLOW VALIDATION ===")
        self.log("  Encoded size: %d (0x%x)", encoded_len, encoded_len)
        self.log("  Allocated (bug): %d (0x%x) bytes  <- (N/4)*3", alloc_size, alloc_size)
        self.log("  Actual decoded: %d (0x%x) bytes", raw_size, raw_size)
        self.log("  Should alloc:   %d (0x%x) bytes  <- ceil(N*3/4)", correct_size, correct_size)
        self.log("  OVERFLOW:       %d bytes", overflow)

        if overflow > 0:
            self.log("  *** VULNERABILITY TRIGGERED: %d-byte heap overflow ***", overflow)
            self.log("  Contents of overflow (hex): %s", raw_payload[alloc_size:alloc_size + overflow].hex())
        else:
            self.log("  (No overflow — encoded size is multiple of 4)")
        self.log("  =============================")
        self.log("")

    # ─── Convenience ────────────────────────────────────────────────────

    def wait_for_requests(self, count=1, timeout=15):
        """Wait until at least `count` total requests are received, or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if len(self.all_requests) >= count:
                return True
            time.sleep(0.1)
        return False

    def received_connect(self):
        """Check if opnum 1 was received."""
        return any(r["opnum"] == 1 for r in self.all_requests)

    def received_telephone(self):
        """Check if opnum 49 was received."""
        return any(r["opnum"] == 49 for r in self.all_requests)

    def get_request(self, opnum):
        """Get the first request with given opnum."""
        for r in self.all_requests:
            if r["opnum"] == opnum:
                return r
        return None


# ─── Self-Test (run standalone) ──────────────────────────────────────────────

def main():
    """Run a quick self-test of the mock server."""
    port = 24444 if len(sys.argv) < 2 else int(sys.argv[1])
    server = MockTSLSPServer(port=port, verbose=True)
    server.start()

    print(f"\n{'='*60}")
    print(f"  Mock TSLSP RPC Server running on 127.0.0.1:{port}")
    print(f"  UUID: {TSLSP_UUID_STR}")
    print(f"  Supported opnums: 1 (Connect), 49 (TelephoneRegisterLKP)")
    print(f"{'='*60}\n")

    print("  To test with the exploit module:")
    print(f"    python3 armagedon.py")
    print(f"    use exploits/cve_2024_38077_madlicense_eop")
    print(f"    set MODE CHECK")
    print(f"    set RHOSTS 127.0.0.1:{port}")
    print(f"    set TRANSPORT ncacn_ip_tcp")
    print(f"    set TEST_PORT {port}")
    print(f"    run")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
