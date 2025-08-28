from rest_framework.views import APIView
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from .serializers import RegisterSerializer, ProfileSerializer, MFAVerifySerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from .models import LoginAttempt
from .utils import generate_totp_secret, get_totp_uri, generate_qr_image_bytes, send_password_reset_email
from .tokens import password_reset_token
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
import pyotp
import base64

User = get_user_model()

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class RegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)


class ObtainTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """
        Accepts: username_or_email, password, optional totp_code
        If user has MFA enabled, totp_code is required and must match.
        Returns: access + refresh tokens on success
        """
        data = request.data
        username_or_email = data.get("username_or_email")
        password = data.get("password")
        totp_code = data.get("totp_code")

       
        user_qs = User.objects.filter(username__iexact=username_or_email)
        if not user_qs.exists():
            user_qs = User.objects.filter(email__iexact=username_or_email)
        user = user_qs.first()

        ip = get_client_ip(request)
        attempt = LoginAttempt(username_or_email=username_or_email, ip_address=ip)

        if user is None:
            attempt.success = False
            attempt.reason = "user-not-found"
            attempt.save()
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

       
        auth_username = user.username
        user_auth = authenticate(request, username=auth_username, password=password)
        if user_auth is None:
            attempt.user = user
            attempt.success = False
            attempt.reason = "bad-password"
            attempt.save()
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

       
        if user.mfa_enabled:
            if not totp_code:
                attempt.user = user
                attempt.success = False
                attempt.reason = "mfa-required"
                attempt.save()
                return Response({"detail": "MFA code required."}, status=status.HTTP_403_FORBIDDEN)
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(totp_code, valid_window=1):
                attempt.user = user
                attempt.success = False
                attempt.reason = "mfa-invalid"
                attempt.save()
                return Response({"detail": "Invalid MFA code."}, status=status.HTTP_403_FORBIDDEN)


        refresh = RefreshToken.for_user(user)
        attempt.user = user
        attempt.success = True
        attempt.save()
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": ProfileSerializer(user).data
        }, status=status.HTTP_200_OK)


class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class EnableMFAView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Generates TOTP secret and QR provisioning URI and returns it encoded.
        Client should show QR image for user to scan in authenticator app.
        """
        user = request.user
        if user.mfa_enabled and user.mfa_secret:
            return Response({"detail": "MFA already enabled."}, status=status.HTTP_400_BAD_REQUEST)

        secret = generate_totp_secret()
        user.mfa_secret = secret
        user.save(update_fields=["mfa_secret"])
        uri = get_totp_uri(secret, user.username, issuer_name="SecureAuthApp")
        qr_bytes = generate_qr_image_bytes(uri)
        qr_b64 = base64.b64encode(qr_bytes).decode()
        
        return Response({
            "secret": secret,
            "provisioning_uri": uri,
            "qr_code_base64": qr_b64
        })


class VerifyMFAEnableView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]
        user = request.user
        if not user.mfa_secret:
            return Response({"detail": "No MFA setup found."}, status=status.HTTP_400_BAD_REQUEST)
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code, valid_window=1):
            user.mfa_enabled = True
            user.save(update_fields=["mfa_enabled"])
            return Response({"detail": "MFA enabled."})
        return Response({"detail": "Invalid MFA code."}, status=status.HTTP_400_BAD_REQUEST)


class DisableMFAView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        user.mfa_enabled = False
        user.mfa_secret = ""
        user.save(update_fields=["mfa_enabled", "mfa_secret"])
        return Response({"detail": "MFA disabled."})


class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"detail": "Provide email."}, status=status.HTTP_400_BAD_REQUEST)
        user_qs = User.objects.filter(email__iexact=email)
        if not user_qs.exists():
          
            return Response({"detail": "If the email exists, a reset link has been sent."})
        user = user_qs.first()
        send_password_reset_email(user, request, password_reset_token)
        return Response({"detail": "If the email exists, a reset link has been sent."})


class ResetPasswordConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"detail": "Invalid link."}, status=status.HTTP_400_BAD_REQUEST)

        if not password_reset_token.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        new_password = request.data.get("password")
        if not new_password:
            return Response({"detail": "Provide new password."}, status=status.HTTP_400_BAD_REQUEST)
      
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(new_password, user)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password reset successful."})


class AdminOnlyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if request.user.role != "admin":
            return Response({"detail": "Forbidden."}, status=status.HTTP_403_FORBIDDEN)
        return Response({"detail": "Hello admin!"})
