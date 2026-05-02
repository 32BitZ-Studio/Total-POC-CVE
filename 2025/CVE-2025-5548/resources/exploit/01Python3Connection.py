import socket

# Define the target server IP and Port
target_ip = '127.0.0.1'
target_port = 21

try:
	# Create a socket object and connect to the server
	print('Exploit> Connect to target')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target_ip, target_port))

	# Receive banner from server
	banner = s.recv(1024).decode('utf-8', errors='ignore')
	print(f'Server> {banner}')

	# Send USER command
	print('Exploit> Send USER command')
	s.send(b'USER anonymous\r\n')

	# Receive the response
	response = s.recv(1024).decode('utf-8', errors='ignore')
	print(f'Server> {response}')

	# Send PASS command
	print('Exploit> Send PASS command')
	s.send(b'PASS anonymous\r\n')

	# Receive the response
	response = s.recv(1024).decode('utf-8', errors='ignore')
	print(f'Server> {response}')

	# Send NOOP command
	print('Exploit> Send NOOP command')
	s.send(b'NOOP test\r\n')

	# Receive the response
	response = s.recv(1024).decode('utf-8', errors='ignore')
	print(f'Server> {response}')

except Exception as e:
	# Exception handling
	print(f'An error occurred: {str(e)}')

finally:
	# Close the connection
	s.close()
