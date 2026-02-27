import os
import requests
import json
from dotenv import load_dotenv

load_dotenv(override=True)

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL")
BREVO_SENDER_NAME = os.getenv("BREVO_SENDER_NAME")

print(f"DEBUG: EmailService (Re)Loaded. Sender: {BREVO_SENDER_EMAIL}")

class EmailService:
    @staticmethod
    def send_transactional_email(to_email, subject, html_content, text_content=None):
        # Fresh reload inside the method to be absolutely sure
        load_dotenv(override=True)
        api_key = os.getenv("BREVO_API_KEY")
        sender_email = os.getenv("BREVO_SENDER_EMAIL")
        sender_name = os.getenv("BREVO_SENDER_NAME")

        if not api_key:
            print(f"ERROR: BREVO_API_KEY not found. Email to {to_email} not sent.")
            return False
        
        print(f"DEBUG: Sending email from {sender_email} to {to_email} using key {api_key[:10]}...")
        
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json"
        }
        
        payload = {
            "sender": {
                "name": BREVO_SENDER_NAME,
                "email": BREVO_SENDER_EMAIL
            },
            "to": [
                {
                    "email": to_email
                }
            ],
            "subject": subject,
            "htmlContent": html_content,
            "textContent": text_content or subject # Fallback to subject if no text provided
        }
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            if response.status_code in [201, 202, 200]:
                print(f"SUCCESS: Email sent to {to_email}")
                return True
            else:
                print(f"ERROR: Brevo failed with {response.status_code}: {response.text}")
                return False
        except Exception as e:
            print(f"EXCEPTION sending email: {str(e)}")
            return False

    @staticmethod
    def send_reset_password_email(to_email, username, reset_link):
        subject = "Reset Your Password - Randaframes"
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <h2 style="color: #3b82f6;">Password Reset Request</h2>
            <p>Hello <strong>{username}</strong>,</p>
            <p>We received a request to reset your password. Click the button below to set a new one:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
            </div>
            <p>This link will expire in 1 hour. If you didn't request this, you can safely ignore this email.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
            <p style="font-size: 12px; color: #666;">This is an automated message from Randaframes Limited.</p>
        </div>
        """
        text_content = f"Hello {username}, we received a request to reset your password. Please use the reset button in the HTML version of this email to set a new one. This link will expire in 1 hour."
        return EmailService.send_transactional_email(to_email, subject, html_content, text_content)

    @staticmethod
    def send_verification_email(to_email, username, verification_link):
        subject = "Verify Your Email - Randaframes"
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <h2 style="color: #10b981;">Welcome to Randaframes!</h2>
            <p>Hello <strong>{username}</strong>,</p>
            <p>Thank you for joining. Please verify your email address to activate your account:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_link}" style="background-color: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email</a>
            </div>
            <p>If you didn't create this account, please ignore this message.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
            <p style="font-size: 12px; color: #666;">This is an automated message from Randaframes Limited.</p>
        </div>
        """
        text_content = f"Welcome to Randaframes, {username}! Please verify your email address to activate your account by clicking the verification button in the HTML version of this email. If you didn't create this account, please ignore this message."

        return EmailService.send_transactional_email(to_email, subject, html_content, text_content)

    @staticmethod
    def send_suspension_status_email(to_email, name, entity_type, status):
        """
        Sends an email regarding suspension or activation status.
        entity_type: "Organisation" or "User account"
        status: "Suspended" or "Activated"
        """
        subject = f"{entity_type} {status} - Randaframes"
        color = "#ef4444" if status == "Suspended" else "#10b981"
        
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <h2 style="color: {color};">{entity_type} {status}</h2>
            <p>Hello <strong>{name}</strong>,</p>
            <p>This is to inform you that your {entity_type.lower()} has been <strong>{status.lower()}</strong> by the system administrator.</p>
            <p>{"If you believe this is an error or have questions, please contact our support team." if status == "Suspended" else "You can now login and continue using our services."}</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
            <p style="font-size: 12px; color: #666;">This is an automated message from Randaframes Limited.</p>
        </div>
        """
        text_content = f"Hello {name}, your {entity_type.lower()} has been {status.lower()} by the administrator."
        return EmailService.send_transactional_email(to_email, subject, html_content, text_content)
