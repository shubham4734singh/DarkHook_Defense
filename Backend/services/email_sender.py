import errno
import smtplib
import ssl
from email.message import EmailMessage
import httpx
from core.config import settings

def _send_email_otp_via_api(to_email: str, otp: str) -> None:
    """Send OTP email using Brevo HTTP API."""
    if not settings.BREVO_API_KEY:
        raise RuntimeError("BREVO_API_KEY not configured")
    
    if not settings.SMTP_FROM:
        raise RuntimeError("SMTP_FROM not configured")
    
    # Split OTP digits for the styled boxes
    otp_boxes = "".join(
        f'<td style="width:44px;height:52px;background:#f9f9f9;border:2px solid #222;'
        f'border-radius:8px;text-align:center;vertical-align:middle;'
        f'font-size:26px;font-weight:700;color:#111;letter-spacing:2px;'
        f'font-family:\'Courier New\',monospace;">{d}</td>'
        for d in otp
    )

    html_body = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="500" cellpadding="0" cellspacing="0"
           style="background:#ffffff;border:1px solid #e0e0e0;
                  border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.06);">

      <tr><td style="padding:36px 40px 12px;text-align:center;border-bottom:1px solid #eee;">
        <div style="font-size:28px;font-weight:800;color:#111;letter-spacing:0.5px;">
          DarkHook Defense
        </div>
        <div style="margin-top:6px;font-size:12px;color:#999;letter-spacing:1.5px;text-transform:uppercase;">
          Phishing Detection Engine
        </div>
      </td></tr>

      <tr><td style="padding:32px 40px 10px;text-align:center;">
        <div style="font-size:20px;font-weight:600;color:#222;">Verify Your Email</div>
        <div style="margin-top:12px;font-size:14px;color:#666;line-height:1.7;">
          Enter the code below to complete your verification.<br>
          This code expires in <strong style="color:#111;">{settings.OTP_TTL_MINUTES} minutes</strong>.
        </div>
      </td></tr>

      <tr><td style="padding:24px 40px;" align="center">
        <table role="presentation" cellpadding="0" cellspacing="6">
          <tr>{otp_boxes}</tr>
        </table>
      </td></tr>

      <tr><td style="padding:16px 48px 20px;text-align:center;">
        <div style="background:#fafafa;border-left:3px solid #333;padding:14px 20px;
                    border-radius:0 8px 8px 0;text-align:left;">
          <div style="font-size:13px;color:#555;font-style:italic;line-height:1.6;">
            &ldquo;The best defense against phishing is awareness. Stay vigilant, stay safe.&rdquo;
          </div>
          <div style="margin-top:6px;font-size:11px;color:#999;font-weight:600;">
            &mdash; DarkHook Defense Team
          </div>
        </div>
      </td></tr>

      <tr><td style="padding:6px 40px 12px;text-align:center;">
        <div style="display:inline-block;background:#fff5f5;border:1px solid #fecaca;
                    border-radius:6px;padding:10px 18px;">
          <span style="font-size:12px;color:#b91c1c;">
            &#x26a0;&#xfe0f; Didn&rsquo;t request this? You can safely ignore this email.
          </span>
        </div>
      </td></tr>

      <tr><td style="padding:20px 40px 28px;text-align:center;border-top:1px solid #eee;">
        <div style="font-size:12px;color:#aaa;line-height:1.5;">
          This is an automated message from <strong style="color:#888;">DarkHook Defense</strong>.<br>
          Please do not reply to this email.
        </div>
        <div style="margin-top:10px;font-size:11px;color:#ccc;">
          &copy; 2026 DarkHook Defense &mdash; Protecting you from phishing threats.
        </div>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    plain_text = (
        "Your DarkHook Defense verification code is:\n\n"
        f"  {otp}\n\n"
        f"This code expires in {settings.OTP_TTL_MINUTES} minutes.\n\n"
        "\"The best defense against phishing is awareness. Stay vigilant, stay safe.\"\n"
        "  — DarkHook Defense Team\n\n"
        "If you did not request this code, you can ignore this email.\n"
    )

    sender_email = settings.SMTP_FROM.split("<")[-1].strip(">") if "<" in settings.SMTP_FROM else settings.SMTP_FROM
    payload = {
        "sender": {"email": sender_email, "name": "DarkHook Defense"},
        "to": [{"email": to_email}],
        "subject": "Your DarkHook Defense Verification Code",
        "htmlContent": html_body,
        "textContent": plain_text
    }

    headers = {
        "accept": "application/json",
        "api-key": settings.BREVO_API_KEY,
        "content-type": "application/json"
    }

    with httpx.Client(timeout=30.0) as client:
        response = client.post(settings.BREVO_API_URL, json=payload, headers=headers)
        response.raise_for_status()

def send_otp_email(to_email: str, otp: str) -> None:
    """Send verification OTP email."""
    if settings.OTP_EMAIL_SENDING_DISABLED:
        print(f"[DEV] OTP for {to_email}: {otp}")
        return

    # Try Brevo API first (recommended for Render/free hosting)
    if settings.BREVO_API_KEY:
        try:
            _send_email_otp_via_api(to_email, otp)
            return
        except Exception as api_error:
            print(f"⚠️ Brevo API failed: {api_error}. Checking SMTP fallback...")

    # Fallback to SMTP (only if fully configured)
    smtp_configured = all([settings.SMTP_HOST, settings.SMTP_USERNAME, settings.SMTP_PASSWORD, settings.SMTP_FROM])
    
    if not smtp_configured:
        if settings.BREVO_API_KEY:
            raise RuntimeError("Email sending failed: Brevo API error and SMTP not configured")
        else:
            raise RuntimeError("Email sending not configured: Set BREVO_API_KEY or configure SMTP")

    # Split OTP digits for the styled boxes
    otp_boxes = "".join(
        f'<td style="width:44px;height:52px;background:#f9f9f9;border:2px solid #222;'
        f'border-radius:8px;text-align:center;vertical-align:middle;'
        f'font-size:26px;font-weight:700;color:#111;letter-spacing:2px;'
        f'font-family:\'Courier New\',monospace;">{d}</td>'
        for d in otp
    )

    html_body = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="500" cellpadding="0" cellspacing="0"
           style="background:#ffffff;border:1px solid #e0e0e0;
                  border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.06);">

      <!-- Header -->
      <tr><td style="padding:36px 40px 12px;text-align:center;border-bottom:1px solid #eee;">
        <div style="font-size:28px;font-weight:800;color:#111;letter-spacing:0.5px;">
          DarkHook Defense
        </div>
        <div style="margin-top:6px;font-size:12px;color:#999;letter-spacing:1.5px;text-transform:uppercase;">
          Phishing Detection Engine
        </div>
      </td></tr>

      <!-- Greeting -->
      <tr><td style="padding:32px 40px 10px;text-align:center;">
        <div style="font-size:20px;font-weight:600;color:#222;">Verify Your Email</div>
        <div style="margin-top:12px;font-size:14px;color:#666;line-height:1.7;">
          Enter the code below to complete your verification.<br>
          This code expires in <strong style="color:#111;">{settings.OTP_TTL_MINUTES} minutes</strong>.
        </div>
      </td></tr>

      <!-- OTP Code -->
      <tr><td style="padding:24px 40px;" align="center">
        <table role="presentation" cellpadding="0" cellspacing="6">
          <tr>{otp_boxes}</tr>
        </table>
      </td></tr>

      <!-- Inspirational Quote -->
      <tr><td style="padding:16px 48px 20px;text-align:center;">
        <div style="background:#fafafa;border-left:3px solid #333;padding:14px 20px;
                    border-radius:0 8px 8px 0;text-align:left;">
          <div style="font-size:13px;color:#555;font-style:italic;line-height:1.6;">
            &ldquo;The best defense against phishing is awareness. Stay vigilant, stay safe.&rdquo;
          </div>
          <div style="margin-top:6px;font-size:11px;color:#999;font-weight:600;">
            &mdash; DarkHook Defense Team
          </div>
        </div>
      </td></tr>

      <!-- Warning -->
      <tr><td style="padding:4px 40px 28px;text-align:center;">
        <div style="display:inline-block;background:#fff5f5;border:1px solid #fecaca;
                    border-radius:6px;padding:10px 18px;">
          <span style="font-size:12px;color:#b91c1c;">
            &#x26a0;&#xfe0f; Didn&rsquo;t request this? You can safely ignore this email.
          </span>
        </div>
      </td></tr>

      <!-- Footer -->
      <tr><td style="padding:20px 40px 28px;text-align:center;border-top:1px solid #eee;">
        <div style="font-size:12px;color:#aaa;line-height:1.5;">
          This is an automated message from <strong style="color:#888;">DarkHook Defense</strong>.<br>
          Please do not reply to this email.
        </div>
        <div style="margin-top:10px;font-size:11px;color:#ccc;">
          &copy; 2026 DarkHook Defense &mdash; Protecting you from phishing threats.
        </div>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    plain_text = (
        "Your DarkHook Defense verification code is:\n\n"
        f"  {otp}\n\n"
        f"This code expires in {settings.OTP_TTL_MINUTES} minutes.\n\n"
        "\"The best defense against phishing is awareness. Stay vigilant, stay safe.\"\n"
        "  — DarkHook Defense Team\n\n"
        "If you did not request this code, you can ignore this email.\n"
    )

    msg = EmailMessage()
    msg["Subject"] = "Your DarkHook Defense Verification Code"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg.set_content(plain_text)
    msg.add_alternative(html_body, subtype="html")

    # Gmail "App Passwords" are often copied with spaces for readability; strip them.
    smtp_password = (settings.SMTP_PASSWORD or "").replace(" ", "")

    def _try_send(use_ssl: bool, port: int) -> None:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(settings.SMTP_HOST, port, timeout=settings.SMTP_TIMEOUT_SECONDS, context=context) as server:
                server.login(settings.SMTP_USERNAME, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(settings.SMTP_HOST, port, timeout=settings.SMTP_TIMEOUT_SECONDS) as server:
                server.ehlo()
                if settings.SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                server.login(settings.SMTP_USERNAME, smtp_password)
                server.send_message(msg)

    try:
        primary_port = settings.SMTP_SSL_PORT if settings.SMTP_USE_SSL else settings.SMTP_PORT
        _try_send(settings.SMTP_USE_SSL, primary_port)
        return
    except (OSError, smtplib.SMTPException) as exc:
        should_fallback = (
            settings.SMTP_FALLBACK_TO_SSL
            and not settings.SMTP_USE_SSL
            and isinstance(exc, OSError)
            and getattr(exc, "errno", None) in {errno.ENETUNREACH, errno.EHOSTUNREACH}
        )
        if should_fallback:
            try:
                _try_send(True, settings.SMTP_SSL_PORT)
                return
            except Exception:
                pass

        hint = ""
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
            hint = (
                " Outbound SMTP may be blocked in this hosting environment. "
                "On Render/hosted platforms, prefer an email provider API (SendGrid/Mailgun/Resend) "
                "or configure allowed egress."
            )
        raise RuntimeError(
            f"SMTP send failed (host={settings.SMTP_HOST}, port={(settings.SMTP_SSL_PORT if settings.SMTP_USE_SSL else settings.SMTP_PORT)}, ssl={settings.SMTP_USE_SSL}, tls={settings.SMTP_USE_TLS}): {exc}.{hint}"
        )
