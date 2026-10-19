"""MFA state is serialized in PostgreSQL across all workers and replicas."""
import hashlib
import hmac
import math
import re
from datetime import timedelta

import pyotp
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import Throttled

from audit_logging.models import AuditLog
from .models import MFAConsumedChallenge, MFAInvalidAttemptBucket, MFAState, User


def fingerprint(secret):
    return hashlib.sha256((secret or "").encode()).hexdigest()


def limited_attempt(state, limit=5):
    now = timezone.now()
    elapsed = (now - state.window_started_at).total_seconds()
    if elapsed >= 60:
        state.window_started_at, state.attempts = now, 0
    if state.attempts >= limit:
        return max(1, math.ceil(60 - elapsed))
    state.attempts += 1
    state.save()
    return None


def limit_invalid_challenge(request):
    # Do not trust a caller-supplied X-Forwarded-For for security buckets.
    key = fingerprint("invalid-mfa:" + request.META.get("REMOTE_ADDR", "unknown"))
    with transaction.atomic():
        MFAInvalidAttemptBucket.objects.get_or_create(key=key)
        bucket = MFAInvalidAttemptBucket.objects.select_for_update().get(key=key)
        wait = limited_attempt(bucket, limit=30)
    if wait:
        raise Throttled(wait=wait, detail="Too many invalid MFA sessions. Try again later.")


def locked_state(user):
    # Call only while holding the User row lock (including initial creation).
    return MFAState.objects.get_or_create(user=user)[0]


def begin_enrollment(user_id):
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user_id)
        if user.mfa_secret:
            return None
        state = locked_state(user)
        if not state.pending_secret or not state.pending_expires_at or state.pending_expires_at <= timezone.now():
            state.pending_secret = pyotp.random_base32()
            state.pending_expires_at = timezone.now() + timedelta(minutes=10)
            state.save()
            AuditLog.objects.create(user=user, action="mfa_enrollment_started", metadata={})
        return state.pending_secret


def matching_counter(secret, code):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    counter = int(timezone.now().timestamp()) // totp.interval
    # Prefer the newest match in the exceedingly rare event of a collision.
    for step in (counter + 1, counter, counter - 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def verify_factor(user_id, code, *, enrollment=False, challenge=None):
    """Return (error, wait); commit failed attempts rather than rolling them back."""
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user_id)
        if not user.is_active:
            return "invalid_session", None
        state = locked_state(user)
        wait = limited_attempt(state)
        if wait:
            return "throttled", wait
        if enrollment:
            if user.mfa_secret:
                return "already_enabled", None
            if not state.pending_secret or not state.pending_expires_at or state.pending_expires_at <= timezone.now():
                return "enrollment_expired", None
            secret = state.pending_secret
        else:
            secret = user.mfa_secret
            if not secret or challenge.get("mfa_fingerprint") != fingerprint(secret):
                return "invalid_session", None
            digest = fingerprint(challenge["jti"])
            if MFAConsumedChallenge.objects.filter(pk=digest).exists():
                return "invalid_session", None
        counter = matching_counter(secret, code)
        previous = state.last_counter if state.secret_fingerprint == fingerprint(secret) else -1
        if counter is None or counter <= previous:
            return "invalid_mfa_code", None
        state.last_counter = counter
        state.secret_fingerprint = fingerprint(secret)
        if enrollment:
            user.mfa_secret, user.mfa_enabled = secret, True
            user.save(update_fields=["mfa_secret", "mfa_enabled"])
            state.pending_secret, state.pending_expires_at = "", None
        else:
            MFAConsumedChallenge.objects.create(
                challenge_hash=digest,
                expires_at=timezone.datetime.fromtimestamp(challenge["exp"], tz=timezone.get_default_timezone()),
            )
            MFAConsumedChallenge.objects.filter(expires_at__lt=timezone.now()).delete()
        state.save()
        AuditLog.objects.create(user=user, action="mfa_enabled" if enrollment else "mfa_login_verified", metadata={})
        return None, None
