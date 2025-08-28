#  Secure Authentication System (Django + DRF)

This project implements a secure authentication system with:
- JWT authentication
- Role-based access control (Admin / User)
- Multi-Factor Authentication (MFA) with Google Authenticator (TOTP)
- Password reset via email
- Profile management

---

## 🚀 Setup Instructions

### 1. Clone & Install
```bash
git clone <your_repo_url>
cd secure_auth_project
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Environment Variables (`.env`)
Create a `.env` file in your project root:
```env
SECRET_KEY=your_django_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost

# JWT
ACCESS_TOKEN_LIFETIME=5
REFRESH_TOKEN_LIFETIME=1440

# Email (for password reset)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your_gmail@gmail.com
EMAIL_HOST_PASSWORD=your_app_password  # Generated in Google Security > App Passwords
```

### 3. Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 4. Create Superuser
```bash
python manage.py createsuperuser
```

### 5. Run Server
```bash
python manage.py runserver
```

---

## 📌 API Endpoints

### 🔹 Auth & Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register/` | Register new user |
| `POST` | `/api/auth/token/` | Login (JWT token) |
| `POST` | `/api/auth/token/refresh/` | Refresh JWT token |
| `GET`  | `/api/auth/profile/` | Get user profile (requires token) |
| `PUT`  | `/api/auth/profile/` | Update profile (requires token) |

---

### 🔹 MFA (Two-Factor Authentication)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/mfa/enable/` | Start MFA (returns secret + QR code URL) |
| `POST` | `/api/auth/mfa/verify-enable/` | Verify MFA code to enable |
| `POST` | `/api/auth/mfa/disable/` | Disable MFA |

---

### 🔹 Password Reset
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/password/forgot/` | Send reset link to email |
| `POST` | `/api/auth/password/reset-confirm/<uidb64>/<token>/` | Confirm new password |

---

### 🔹 Role-based Access
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/admin-only/` | Example protected route (Admin only) |

---

## 📬 Sample Requests & Responses

### 1. Register
**Request:**
```http
POST /api/auth/register/
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "password": "StrongPass123!",
  "role": "user"
}
```

**Response:**
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "mfa_enabled": false
}
```

---

### 2. Login
**Request:**
```http
POST /api/auth/token/
Content-Type: application/json

{
  "username": "alice",
  "password": "StrongPass123!"
}
```

**Response:**
```json
{
  "access": "jwt_access_token_here",
  "refresh": "jwt_refresh_token_here",
  "mfa_required": false
}
```

---

### 3. Enable MFA
**Request:**
```http
POST /api/auth/mfa/enable/
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/SecureApp:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureApp"
}
```

---

### 4. Verify MFA
**Request:**
```http
POST /api/auth/mfa/verify-enable/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "code": "123456"
}
```

**Response:**
```json
{ "message": "MFA enabled successfully" }
```

---

### 5. Forgot Password
**Request:**
```http
POST /api/auth/password/forgot/
Content-Type: application/json

{
  "email": "alice@example.com"
}
```

**Response:**
```json
{ "message": "Password reset link sent to email" }
```

---

### 6. Reset Password (via email link)
**Request:**
```http
POST /api/auth/password/reset-confirm/<uidb64>/<token>/
Content-Type: application/json

{
  "new_password": "NewStrongPass123!"
}
```

**Response:**
```json
{ "message": "Password reset successful" }
```

---

## ✅ Testing with Postman
1. Import API endpoints into Postman.  
2. Register a user → Login → Copy JWT access token.  
3. Use `Authorization: Bearer <token>` header for protected endpoints.  
4. Enable MFA → Scan QR code in Google Authenticator → Verify with code.  
5. Test Admin route with an admin account.  

---

## 🛡 Security Notes
- Use **HTTPS** in production.  
- Store JWT tokens securely (HttpOnly cookies or secure storage).  
- Use **Google App Passwords** for Gmail SMTP.  
- Rotate `SECRET_KEY` in production if compromised.  
