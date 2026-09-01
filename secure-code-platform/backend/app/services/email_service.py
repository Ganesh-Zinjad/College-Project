"""
Email service.

Sends transactional email over SMTP via aiosmtplib. In `APP_ENV=development`
with no SMTP credentials configured, emails are logged to the console
instead of sent — so registration/reset flows are fully testable locally
without a real mail server.
"""
import asyncio
import logging
from email.message import EmailMessage

import aiosmtplib

from app.core.config import settings

logger = logging.getLogger("secure_code_platform.email")


class EmailService:
    def __init__(self):
        self.configured = bool(settings.SMTP_USERNAME and settings.SMTP_PASSWORD)

    def send_verification_email(self, to_email: str, full_name: str, token: str) -> None:
        link = f"{settings.FRONTEND_ORIGIN}/verify-email.html?token={token}"
        html = self._template(
            heading="Verify your email",
            body=f"Hi {full_name}, confirm your email address to activate your Secure Code Platform account.",
            cta_label="Verify email",
            cta_link=link,
        )
        self._dispatch(to_email, "Verify your email — Secure Code Platform", html)

    def send_password_reset_email(self, to_email: str, full_name: str, token: str) -> None:
        link = f"{settings.FRONTEND_ORIGIN}/reset-password.html?token={token}"
        html = self._template(
            heading="Reset your password",
            body=f"Hi {full_name}, we received a request to reset your password. This link expires in "
                 f"{settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes. If you didn't request this, ignore this email.",
            cta_label="Reset password",
            cta_link=link,
        )
        self._dispatch(to_email, "Reset your password — Secure Code Platform", html)

    def send_scan_complete_email(self, to_email: str, full_name: str, scan_name: str, verdict: str, scan_id: str) -> None:
        link = f"{settings.FRONTEND_ORIGIN}/results.html?scan_id={scan_id}"
        html = self._template(
            heading="Your scan is complete",
            body=f"Hi {full_name}, the scan \"{scan_name}\" finished with verdict: {verdict.upper()}.",
            cta_label="View results",
            cta_link=link,
        )
        self._dispatch(to_email, f"Scan complete: {scan_name} — {verdict.upper()}", html)

    def send_critical_vuln_email(self, to_email: str, full_name: str, scan_name: str, count: int, scan_id: str) -> None:
        link = f"{settings.FRONTEND_ORIGIN}/results.html?scan_id={scan_id}"
        html = self._template(
            heading="Critical vulnerabilities detected",
            body=f"Hi {full_name}, scan \"{scan_name}\" found {count} critical-severity issue(s) that need attention.",
            cta_label="Review findings",
            cta_link=link,
        )
        self._dispatch(to_email, f"⚠ Critical vulnerabilities in {scan_name}", html)

    # --- internals ---

    @staticmethod
    def _template(heading: str, body: str, cta_label: str, cta_link: str) -> str:
        return f"""\
<div style="font-family: -apple-system, Segoe UI, sans-serif; background:#0a0e14; padding:32px; color:#e6edf3;">
  <div style="max-width:480px; margin:0 auto; background:#11161f; border:1px solid #1e2733; border-radius:12px; padding:32px;">
    <h2 style="color:#00d4b8; margin-top:0;">{heading}</h2>
    <p style="color:#aab4c2; line-height:1.6;">{body}</p>
    <a href="{cta_link}" style="display:inline-block; margin-top:16px; background:#00d4b8; color:#04130f; text-decoration:none; padding:12px 24px; border-radius:8px; font-weight:600;">{cta_label}</a>
    <p style="color:#6b7686; font-size:12px; margin-top:24px;">Secure Code Vulnerability Detection Platform</p>
  </div>
</div>"""

    def _dispatch(self, to_email: str, subject: str, html_body: str) -> None:
        if not self.configured:
            logger.info("[DEV EMAIL] To: %s | Subject: %s\n%s", to_email, subject, html_body)
            return

        message = EmailMessage()
        message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content("This email requires an HTML-capable client.")
        message.add_alternative(html_body, subtype="html")

        try:
            asyncio.get_event_loop().create_task(self._send_async(message))
        except RuntimeError:
            # No running event loop (e.g. called from a sync context) — send inline.
            asyncio.run(self._send_async(message))

    async def _send_async(self, message: EmailMessage) -> None:
        try:
            await aiosmtplib.send(
                message,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USERNAME,
                password=settings.SMTP_PASSWORD,
                start_tls=settings.SMTP_USE_TLS,
            )
        except Exception:
            logger.exception("Failed to send email to %s", message["To"])
