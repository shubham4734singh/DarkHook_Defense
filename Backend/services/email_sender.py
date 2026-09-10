import httpx
from core.config import settings


def _generate_otp_email_content(otp: str) -> tuple[str, str]:
    """Generate HTML and plain text for verification email."""
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

      <!-- Quote -->
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
        "  — DarkHook Defense Team\n"
    )

    return html_body, plain_text


def send_otp_email(to_email: str, otp: str) -> None:
    """Send verification OTP email using Brevo HTTP API."""
    if settings.OTP_EMAIL_SENDING_DISABLED:
        print(f"[DEV] OTP for {to_email}: {otp}")
        return

    if not settings.BREVO_API_KEY:
        print(f"[DEV] BREVO_API_KEY not configured. OTP for {to_email}: {otp}")
        return

    html_body, plain_text = _generate_otp_email_content(otp)

    raw_from = settings.BREVO_SENDER_EMAIL or settings.SMTP_FROM or "darkhookdefense@gmail.com"
    if "<" in raw_from:
        sender_name = raw_from.split("<")[0].strip() or settings.BREVO_SENDER_NAME
        sender_email = raw_from.split("<")[-1].strip(">")
    else:
        sender_name = settings.BREVO_SENDER_NAME
        sender_email = raw_from

    headers = {
        "accept": "application/json",
        "api-key": settings.BREVO_API_KEY,
        "content-type": "application/json",
    }

    with httpx.Client(timeout=30.0) as client:
        # Validate sender against Brevo account to avoid silent drop if sender email is not authenticated
        try:
            senders_resp = client.get("https://api.brevo.com/v3/senders", headers=headers)
            if senders_resp.status_code == 200:
                active_senders = senders_resp.json().get("senders", [])
                active_emails = [s.get("email", "").strip().lower() for s in active_senders if s.get("active")]
                if active_emails and sender_email.strip().lower() not in active_emails:
                    print(
                        f"[!] [Brevo] Configured sender '{sender_email}' is not validated. Auto-switching to verified sender: '{active_emails[0]}'"
                    )
                    sender_email = active_emails[0]
        except Exception as e:
            print(f"[!] [Brevo] Senders check warning: {e}")

        payload = {
            "sender": {"email": sender_email, "name": sender_name},
            "to": [{"email": to_email}],
            "subject": "Your DarkHook Defense Verification Code",
            "htmlContent": html_body,
            "textContent": plain_text,
        }

        response = client.post(settings.BREVO_API_URL, json=payload, headers=headers)
        response.raise_for_status()
