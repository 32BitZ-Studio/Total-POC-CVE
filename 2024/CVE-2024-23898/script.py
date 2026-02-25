import websocket

url = "ws://localhost:8080/cli/ws"
origin_header = "http://localhost:8080"
ws = websocket.create_connection(url, header=[f"Origin: {origin_header}"])

print("connected")

command = b"help"
print(command)

#the third byte in start is the length of the command: help = 0x4, who-am-i=0x8

start = b"\x00\x00\x04"
end = b"\x02\x00\x05\x55\x54\x46\x2d\x38\x01\x00\x05\x65\x6e\x5f\x55\x53"

command_frame = start + command + end

ws.send(command_frame, opcode=websocket.ABNF.OPCODE_BINARY)

print("command sent")

ws.send(b'\x03', opcode=websocket.ABNF.OPCODE_BINARY)

print("start signal sent")

i=0

try:
    while True:
        response = ws.recv()

        print(f"Message {i}: {response}");
        i += 1
except websocket.WebSocketConnectionClosedException:
    print("Connection closed")
