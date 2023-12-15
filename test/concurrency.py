import lib

import requests
import threading
import random


def test_request(headers):
    try:
        # Replace with the actual URL and endpoint of your server
        
        response = requests.get("http://127.0.0.1:8000", headers=headers, timeout=5)
        print(f"Response Code: {response.status_code}")
    except Exception as e:
        print(f"Request failed: {e}")

# Number of simultaneous requests to simulate
num_requests = 100

threads = []
for i in range(num_requests):
    headers = {
        "Authorization": "Basic " + random.choice(lib.keys + [":"]),
        "Connection": "keep-alive"
    }
    thread = threading.Thread(target=test_request, args=(headers, ))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()
