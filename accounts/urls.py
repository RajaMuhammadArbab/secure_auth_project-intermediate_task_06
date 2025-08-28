from django.urls import path
from .views import (
    RegisterView,
    ObtainTokenView,
    ProfileView,
    EnableMFAView,
    VerifyMFAEnableView,
    DisableMFAView,
    ForgotPasswordView,
    ResetPasswordConfirmView,
    AdminOnlyView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("token/", ObtainTokenView.as_view(), name="token_obtain"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("mfa/enable/", EnableMFAView.as_view(), name="mfa_enable"),
    path("mfa/verify-enable/", VerifyMFAEnableView.as_view(), name="mfa_verify"),
    path("mfa/disable/", DisableMFAView.as_view(), name="mfa_disable"),
    path("password/forgot/", ForgotPasswordView.as_view(), name="forgot_password"),
    path("password/reset-confirm/<str:uidb64>/<str:token>/", ResetPasswordConfirmView.as_view(), name="password_reset_confirm"),
    path("admin-only/", AdminOnlyView.as_view(), name="admin_only"),
]
