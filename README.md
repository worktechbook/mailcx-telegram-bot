# Mail.cx + 2FA TOTP Telegram Webhook Bot

Serverless Python Telegram bot deployed on Vercel that provisions disposable Mail.cx email addresses, extracts incoming 5–6 digit OTP verification codes, and generates RFC 6238 6-digit 2FA TOTP codes from Base32 secrets or `otpauth://` URIs.

## Features
- **Disposable Mail & OTP Fetching**: One-tap inbox creation (`✉️ Get Mail`) and OTP code extraction (`🔑 Get Code`) with automatic inbox cleanup
- **Built-in 2FA TOTP Generator**: Send any Base32 TOTP secret or `otpauth://totp/...` URI to receive a copyable 6-digit code
- **Serverless Vercel Architecture**: Zero-framework Python `BaseHTTPRequestHandler` with only `requests` as an external dependency
- **Optional Webhook Secret Validation**: Verifies `X-Telegram-Bot-Api-Secret-Token` when `WEBHOOK_SECRET` is configured

## Environment Variables
See `.env.example` (`BOT_TOKEN`, optional `WEBHOOK_SECRET`, optional `MAILCX_DOMAIN`).

## Deploy to Vercel
1. Configure `BOT_TOKEN` (and `WEBHOOK_SECRET`) in Vercel Project Environment Variables.
2. Deploy with `vercel --prod`.
3. Register your webhook:
   ```bash
   curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
     -d "url=https://<your-deployment>.vercel.app/api/webhook" \
     -d "secret_token=<WEBHOOK_SECRET>"
   ```
