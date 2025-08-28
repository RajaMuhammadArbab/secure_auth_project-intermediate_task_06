import pyotp
import qrcode
import io
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer_name="SecureAuthApp"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def generate_qr_image_bytes(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()

def send_password_reset_email(user, request, token_generator):
    from django.utils.http import urlsafe_base64_encode
    from django.utils.encoding import force_bytes
    from django.contrib.sites.shortcuts import get_current_site

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = token_generator.make_token(user)
  
    reset_path = f"/reset-password-confirm/{uid}/{token}/"
   
    frontend_base = getattr(settings, "FRONTEND_BASE", "")
    reset_url = f"{frontend_base}{reset_path}"

    subject = "Password reset request"
    message = f"Hello {user.username},\n\nUse this link to reset your password:\n{reset_url}\n\nIf you didn't request this, ignore.\n"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
