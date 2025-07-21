from django.dispatch import receiver, Signal
from django_q.tasks import async_task
from authentication.models import User
from datetime import timedelta
from django.utils.timezone import now
from .libs.utils import send_otp_email as soe, generate_otp

# Define custom signals
user_registered = Signal()
user_logged_in = Signal()
user_logged_out = Signal()
mfa_setup = Signal()
mfa_verified = Signal()
mfa_login_attempt = Signal()
user_token_refreshed = Signal()

# Signal handlers
@receiver(user_registered)
def handle_user_registration(sender, user, metadata, **kwargs):
    async_task(send_otp_email, metadata.get('email'))

@receiver(user_logged_in)
def handle_user_login(sender, user, metadata, **kwargs):
    pass

@receiver(user_logged_out)
def handle_user_logout(sender, user, metadata, **kwargs):
    pass

@receiver(mfa_setup)
def handle_mfa_setup(sender, user, metadata, **kwargs):
    pass

# Receiver for mfa_verified
@receiver(mfa_verified)
def handle_mfa_verified(sender, user, metadata, **kwargs):
    pass

# Receiver for mfa_login_attempt
@receiver(mfa_login_attempt)
def handle_mfa_login_attempt(sender, user, metadata, **kwargs):
    pass

# Receiver for user_token_refreshed
@receiver(user_token_refreshed)
def handle_token_refresh(sender, user, metadata, **kwargs):
    pass

def send_otp_email(email):
    otp = generate_otp()
    soe(email=email, otp=otp)
    user = User.objects.get(email=email)
    user.otp = otp
    user.otp_expiration = now() + timedelta(minutes=10)
    user.last_otp_sent = now()
    user.save()
