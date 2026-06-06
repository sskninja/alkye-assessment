-- Extend email_logs to support 2FA OTP expiry and one-time-use enforcement
ALTER TABLE email_logs
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
    ADD COLUMN IF NOT EXISTS used       BOOLEAN      NOT NULL DEFAULT false;
