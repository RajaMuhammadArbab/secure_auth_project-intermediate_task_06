from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User, LoginAttempt

@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "role", "is_staff", "is_active", "mfa_enabled")
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Security", {"fields": ("role", "mfa_enabled", "mfa_secret")}),
    )

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("username_or_email", "ip_address", "timestamp", "success", "reason")
    readonly_fields = ("timestamp",)
