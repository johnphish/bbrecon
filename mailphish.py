import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import makedate, formatdate
import time
import socket

# --- Configuration for Illumination ---
# REPLACE THESE WITH YOUR DOMAIN AND IP
SENDER_DOMAIN = "your-target-domain.com" # The domain you control and have configured DNS for
SENDER_EMAIL = f"support@{SENDER_DOMAIN}" # The 'From' address the recipient sees
RECIPIENT_EMAIL = "target@recipient-domain.com"
SMTP_SERVER_IP = "123.45.67.89" # Your dedicated server's public IP address

# The Template of Deception
EMAIL_TEMPLATE = """\
<html>
  <body>
    <p>Greetings, </p>
    <p>This is a critical update regarding your account security. Please review the attached document immediately.</p>
    <p>Sincerely,</p>
    <p>The {Domain_Name} Team</p>
  </body>
</html>
"""

def forge_the_message(template_data):
    """Crafts the MIMEMultipart message with precise, non-negotiable headers."""
    msg = MIMEMultipart('alternative')
    
    # Critical Headers: Absolute Control
    msg['Subject'] = "URGENT: Security Policy Update Required"
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL
    
    # Date Header: Ensures proper chronological order
    msg['Date'] = formatdate(time.time(), localtime=True)
    
    # Message-ID: Forged for consistency, using the SENDER_DOMAIN
    # A true Message-ID is crucial for DMARC/DKIM alignment
    msg['Message-ID'] = f"<{time.time()}.{socket.gethostname()}@{SENDER_DOMAIN}>"

    # Insert the template content
    html_part = MIMEText(template_data.format(Domain_Name=SENDER_DOMAIN.split('.')[0].capitalize()), 'html')
    msg.attach(html_part)
    
    return msg.as_string()

def liberate_the_mail(message):
    """Connects directly to a designated target's mail server (MTA)."""
    try:
        # Step 1: Establish the link to your own, liberated MTA (running on the specified IP)
        # We are using port 25 for raw, unencrypted transfer for demonstration,
        # but port 587 with TLS is often required by receiving servers.
        with smtplib.SMTP(SMTP_SERVER_IP, 25) as server:
            # EHLO/HELO: Introduce our liberated server. This name must resolve to the IP!
            server.ehlo(SENDER_DOMAIN)
            
            # MAIL FROM: The 'envelope' sender, which must align with SPF
            server.mail(SENDER_EMAIL)
            
            # RCPT TO: The recipient for the envelope
            server.rcpt(RECIPIENT_EMAIL)
            
            # DATA: Send the forged message data
            server.data(message)
            print(f"**SUCCESS:** Mail liberated from {SENDER_EMAIL} to {RECIPIENT_EMAIL} via our sovereign MTA.")

    except Exception as e:
        print(f"**FAILURE:** A mortal chain attempted to bind: {e}")
        # In a real operation, we would implement complex retry logic and server rotation

if __name__ == "__main__":
    forged_message = forge_the_message(EMAIL_TEMPLATE)
    liberate_the_mail(forged_message)
