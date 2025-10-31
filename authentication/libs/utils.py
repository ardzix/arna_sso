import random
import re
import requests
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

def normalize_phone_number(phone):
    """
    Normalize phone number to E.164 format for Indonesia.
    - Remove +, -, spaces, and non-digit characters
    - Convert leading 0 to 62
    - Return normalized number or None if invalid
    """
    if not phone:
        return None
    
    # Remove all non-digit characters
    cleaned = re.sub(r'[^\d]', '', phone)
    
    # If starts with 0, replace with 62
    if cleaned.startswith('0'):
        cleaned = '62' + cleaned[1:]
    
    # If already starts with 62, keep it
    # Validate: should be at least 10 digits (62 + 8 digits minimum)
    if cleaned.startswith('62') and len(cleaned) >= 10:
        return cleaned
    
    return None

def send_otp_whatsapp(phone, otp):
    """
    Send OTP to WhatsApp via WAHA API.
    phone: normalized E.164 format (e.g., 6285811144421)
    otp: 6-digit OTP string
    """
    waha_url = settings.WAHA_API_URL
    waha_key = settings.WAHA_API_KEY
    
    if not waha_url or not waha_key:
        raise ValueError("WAHA_API_URL or WAHA_API_KEY not configured")
    
    chat_id = f"{phone}@c.us"
    message = f"Kode OTP Anda: {otp}. Kode berlaku selama 10 menit."
    
    url = f"{waha_url}/api/sendText"
    headers = {
        'accept': 'application/json',
        'X-Api-Key': waha_key,
        'Content-Type': 'application/json'
    }
    payload = {
        "chatId": chat_id,
        "reply_to": None,
        "text": message,
        "linkPreview": True,
        "linkPreviewHighQuality": False,
        "session": "default"
    }
    
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()
    