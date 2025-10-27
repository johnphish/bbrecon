import socket
import time
import os

# The Asterisk 'Manager Interface' (AMI) connection
# We'll use AMI to dynamically place a call with a spoofed Caller ID
# NOTE: This requires AMI to be enabled and configured in /etc/asterisk/manager.conf

def connect_ami_and_call(target_number, spoofed_cli):
    """Connects to AMI and initiates a call with the spoofed CLI."""
    AMI_HOST = '127.0.0.1'
    AMI_PORT = 5038
    AMI_USER = 'phish_user'
    AMI_SECRET = 'unbreakable_chain' # The secret of the free god

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((AMI_HOST, AMI_PORT))
        print("Connected to Asterisk AMI.")

        # 1. Login Command
        login_command = (
            f'Action: Login\r\n'
            f'Username: {AMI_USER}\r\n'
            f'Secret: {AMI_SECRET}\r\n'
            f'Events: off\r\n\r\n'
        )
        s.sendall(login_command.encode('utf-8'))
        time.sleep(1)
        print("AMI Login Sent.")

        # 2. Originate Command (The Chain Breaker)
        # Context and Exten must be configured in /etc/asterisk/extensions.conf 
        # to handle the outbound call and set the spoofed CallerID.
        originate_command = (
            f'Action: Originate\r\n'
            f'Channel: SIP/voip_trunk/{target_number}\r\n' # 'voip_trunk' is defined in sip.conf
            f'Context: outbound-phish\r\n'                  # This context will set the spoofed CallerID
            f'Exten: {target_number}\r\n'
            f'Priority: 1\r\n'
            f'Callerid: "{spoofed_cli}" <{spoofed_cli}>\r\n' # The heart of the spoofing: setting the CallerID
            f'Timeout: 30000\r\n\r\n'
        )
        s.sendall(originate_command.encode('utf-8'))
        print(f"Originate command sent. Calling {target_number} with spoofed ID: {spoofed_cli}")

        time.sleep(2)
        response = s.recv(4096).decode('utf-8')
        print("AMI Response:", response)
        
        # 3. Logoff
        s.sendall(b'Action: Logoff\r\n\r\n')
        s.close()
        print("AMI connection closed.")

    except Exception as e:
        print(f"Error during AMI connection or command execution: {e}")

if __name__ == "__main__":
    target = input("Enter Target Phone Number (e.g., 12223334444): ")
    spoof_id = input("Enter Desired Spoofed Caller ID (e.g., 18005551212): ")
    connect_ami_and_call(target, spoof_id)
