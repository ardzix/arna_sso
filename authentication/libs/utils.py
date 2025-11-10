import random
import re
import requests
import logging
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)

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

def send_otp_to_n8n(phone, otp, webhook_id=None):
    """
    Send OTP data to n8n webhook for reverse WA OTP authentication.
    Instead of pushing message via WAHA, we send data to n8n and user must initiate chat.
    
    phone: normalized E.164 format (e.g., 6285811144421)
    otp: 6-digit OTP string
    webhook_id: Optional webhook ID (UUID), if not provided will use N8N_WEBHOOK_ID from settings
    """
    n8n_url = settings.N8N_WEBHOOK_URL
    n8n_auth = settings.N8N_WEBHOOK_AUTH_TOKEN
    n8n_webhook_id = settings.N8N_WEBHOOK_ID
    
    if not n8n_url:
        error_msg = "N8N_WEBHOOK_URL not configured"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Use webhook_id from parameter, or from settings, or raise error
    final_webhook_id = webhook_id or n8n_webhook_id
    
    if not final_webhook_id:
        error_msg = "N8N_WEBHOOK_ID not configured. Please set N8N_WEBHOOK_ID in settings or provide webhook_id parameter."
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Construct webhook URL: http://n8d.arnatech.id/webhook/{webhook_id}
    webhook_url = f"{n8n_url.rstrip('/')}/{final_webhook_id}"
    
    payload = {
        "phone_number": phone,
        "otp": otp
    }
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    # Add authorization header if token is provided
    if n8n_auth:
        headers['Authorization'] = n8n_auth
    
    try:
        logger.info(f"Sending OTP data to n8n webhook for {phone}, webhook: {webhook_url}")
        response = requests.post(webhook_url, json=payload, headers=headers, timeout=30)
        logger.info(f"N8N webhook response status: {response.status_code}")
        
        if response.status_code not in [200, 201, 202]:
            error_text = response.text
            logger.error(f"N8N webhook returned non-success status: {response.status_code}, Response: {error_text}")
            try:
                error_detail = response.json()
                logger.error(f"N8N webhook error response (JSON): {error_detail}")
            except:
                logger.error(f"N8N webhook error response (Text): {error_text}")
            raise Exception(f"N8N webhook error: {response.status_code} - {error_text}")
        
        try:
            result = response.json()
            logger.info(f"Successfully sent OTP data to n8n for {phone}, Response: {result}")
        except:
            logger.info(f"Successfully sent OTP data to n8n for {phone}, Response: {response.text}")
            result = {"status": "success", "message": response.text}
        
        return result
    except requests.exceptions.Timeout as e:
        error_msg = f"Timeout sending OTP data to n8n for {phone}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg) from e
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error sending OTP data to n8n for {phone}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg) from e
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error sending OTP data to n8n for {phone}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg) from e
    except Exception as e:
        error_msg = f"Unexpected error sending OTP data to n8n for {phone}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise Exception(error_msg) from e
    