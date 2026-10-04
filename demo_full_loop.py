import requests
import json
import time

PROXY_URL = "http://localhost:8000/v1/chat/completions"

def run_test(name, prompt, restore=False):
    print(f"\n--- Running Test: {name} ---")
    print(f"User Prompt: {prompt}")
    
    payload = {
        "model": "gemini-2.5-flash", 
        "messages": [{"role": "user", "content": prompt}]
    }
    
    headers = {"Content-Type": "application/json"}
    
    # Add the magic header to tell the proxy we are authorized to get the real data back
    if restore:
        headers["x-restore-placeholders"] = "true"
        print("[!] Sent authorization header: x-restore-placeholders=true")
        
    try:
        start = time.time()
        response = requests.post(PROXY_URL, json=payload, headers=headers)
        latency = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response ({latency:.2f}s): {data['choices'][0]['message']['content']}")
        else:
            print(f"Error ({response.status_code}): {response.text}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the proxy. Is it running?")

if __name__ == "__main__":
    # Test 1: Standard PII test without restoration (Default app behavior)
    run_test(
        "PII Detection (No Restoration)",
        "Summarize this employee record: Email is rahul.sharma@gmail.com, Aadhaar is 4521 8899 1005, and Phone is 9876543210."
    )
    
    # Test 2: Standard PII test WITH restoration (Privileged app behavior)
    run_test(
        "PII Detection (WITH Restoration)",
        "Summarize this employee record: Email is rahul.sharma@gmail.com, Aadhaar is 4521 8899 1005, and Phone is 9876543210.",
        restore=True
    )
