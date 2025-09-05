import random
import bcrypt
import re
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database.db_connection import DatabaseConnection

class EmailVerification:
    def __init__(self, securescan_email, securescan_password):
        self.email = securescan_email # define new environment variabes
        self.password = securescan_password
        pass

    def send_otp(self, userEmail):
        """Retrieve user email and send OTP."""
        email = self.get_user_email(userEmail)
        if not email:
            return None, "Username not found."

        otp = self.generate_otp()
        success = self.send_email(email, otp)

        if success:
            return otp, None  # OTP sent successfully
        else:
            return None, "Failed to send OTP."

    def get_user_email(self, userEmail):
        return userEmail

    def generate_otp(self):
        """Generate a 6-digit OTP."""
        return str(random.randint(100000, 999999))

    def send_email(self, recipient_email, otp):
        """Send OTP via email."""
        sender_email = self.email
        sender_password = self.password
        subject = "Secure Scan - OTP for Password Reset"
        body = f"Your OTP is: {otp}"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, msg.as_string())
                return True
        except Exception as e:
            print(f"Email error: {e}")
            return False

class OTPVerificationLogic:
    def __init__(self):
        self.otp_store = {}  # Temporary in-memory store: {username: (otp, timestamp)}

    def store_otp(self, username, otp):
        """Stores the OTP with a timestamp."""
        timestamp = time.time()
        self.otp_store[username] = (otp, timestamp)

    def verify_otp(self, username, entered_otp, expiry_seconds=300):
        """Verifies the entered OTP."""
        if username not in self.otp_store:
            return False, "No OTP found for this user."

        stored_otp, timestamp = self.otp_store[username]
        current_time = time.time()

        # Check expiry
        if current_time - timestamp > expiry_seconds:
            del self.otp_store[username]  # Clean up
            return False, "OTP has expired. Please request a new one."

        # Check match
        if entered_otp == stored_otp:
            del self.otp_store[username]  # Invalidate OTP after successful verification
            return True, "OTP verified successfully."
        else:
            return False, "Incorrect OTP."

