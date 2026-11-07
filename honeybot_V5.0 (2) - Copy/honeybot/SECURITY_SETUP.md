# FactoryShield dashboard authentication setup

The dashboard and its JSON API now require an administrator session. Do not commit real credentials or a real secret key to Git.

## Required environment variables

Set these variables in the same terminal that starts FactoryShield:

- `FACTORYSHIELD_SECRET_KEY`: a long random secret used to sign Flask sessions.
- `FACTORYSHIELD_ADMIN_USERNAME`: the dashboard administrator username.
- `FACTORYSHIELD_ADMIN_PASSWORD`: a strong, unique administrator password.
- `FACTORYSHIELD_COOKIE_SECURE`: use `false` for local HTTP development; set to `true` when served over HTTPS.

The application does not load `.env` files automatically. This avoids silently depending on an uninstalled package. The `.env.example` file is a reference only.

## Windows PowerShell (local development)

Run these commands from the `honeybot_V5.0 (2) - Copy/honeybot` directory:

```powershell
$env:FACTORYSHIELD_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:FACTORYSHIELD_ADMIN_USERNAME = "admin"
$env:FACTORYSHIELD_ADMIN_PASSWORD = "Replace-this-with-a-long-unique-password"
$env:FACTORYSHIELD_COOKIE_SECURE = "false"
python run.py
```

Open `http://127.0.0.1:5000` and sign in with the username and password you configured. Choose your own password; do not use the example value above.

## Linux / macOS (local development)

```bash
export FACTORYSHIELD_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export FACTORYSHIELD_ADMIN_USERNAME="admin"
export FACTORYSHIELD_ADMIN_PASSWORD="Replace-this-with-a-long-unique-password"
export FACTORYSHIELD_COOKIE_SECURE="false"
python run.py
```

## Security notes

- The dashboard login is a separate administrator identity. The synthetic employee directory in `enterprise/rbac.py` is used by the honeypot's detection simulation; it is not a store of dashboard login accounts.
- Passwords are hashed with Werkzeug's password hashing helpers before comparison; no administrator password is stored in source code.
- API GET requests require an authenticated session. POST requests also require a session-bound CSRF token sent by the dashboard.
- Session cookies are HttpOnly and SameSite=Lax. Enable Secure cookies when using HTTPS.
- Sessions last 30 minutes. A new login is required after expiration.
- The dashboard binds to localhost by default. Do not expose it publicly until HTTPS, deployment secrets, network isolation, and production-grade rate limiting have been configured and reviewed.
- Keep the real values out of GitHub, screenshots, logs, and the graduation report. If a real secret is ever committed, rotate it immediately.
