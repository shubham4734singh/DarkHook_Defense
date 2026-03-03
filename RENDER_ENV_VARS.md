# Render Environment Variables Setup

⚠️ **IMPORTANT**: Set these in your Render dashboard for the backend to work properly.

Go to: **Render Dashboard → Your Service → Environment → Add Environment Variables**

## Required Variables

```bash
# MongoDB Connection
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<database>?retryWrites=true&w=majority
DATABASE_NAME=Phishing

# JWT Authentication (Generate: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=your_secret_key_here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# CORS & Frontend URL (CRITICAL - Must match your production domain)
FRONTEND_URL=https://darkhookdefense.online
BACKEND_URL=https://darkhook-defense.onrender.com

# SMTP Email (Brevo)
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USERNAME=your_brevo_login@smtp-brevo.com
SMTP_PASSWORD=your_brevo_smtp_key_here
SMTP_FROM=DarkHook Defense <your_verified_email@domain.com>
SMTP_USE_TLS=true
SMTP_TIMEOUT_SECONDS=30

# Email Verification
REQUIRE_EMAIL_VERIFICATION=true
OTP_TTL_MINUTES=10
OTP_RESEND_COOLDOWN_SECONDS=60
OTP_MAX_ATTEMPTS=5
```

## After Adding Variables

1. **Save** all environment variables
2. **Redeploy** your service (Render will auto-redeploy when you update env vars)
3. Wait for deployment to complete (~2-3 minutes)
4. Test registration at `https://darkhookdefense.online`

## Troubleshooting

### CORS Errors Persist
- Verify `FRONTEND_URL=https://darkhookdefense.online` (no trailing slash)
- Check Render logs for errors: Dashboard → Logs tab

### Email OTP Not Sending
- Verify `SMTP_TIMEOUT_SECONDS=30` is set
- Check Render logs for SMTP errors

### 400/500 Errors
- Check Render logs for detailed error messages
- Verify MongoDB connection string is correct
- Ensure all required variables are set
