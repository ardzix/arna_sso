import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    """Generate a random 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    """Send OTP to the user's email."""
    subject = "Verify Your Email Address"
    message = f"Your OTP is: {otp}. It expires in 10 minutes."
    sent = send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
    print(subject, sent)
    