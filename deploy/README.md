# Deployment hardening

The application emits security headers and blocks dangerous behaviour in code,
but the web server is still the first line of defence. Apply the files in this
directory in production.

## nginx (production image)

The `Dockerfile` uses `richarvey/nginx-php-fpm`, so `.htaccess` is ignored.

1. Copy the snippet into the image (the Dockerfile already places it at
   `/etc/nginx/snippets/jumpproptech-security.conf`).
2. Include it inside the API `server { ... }` block, before `location /`:

   ```nginx
   include /etc/nginx/snippets/jumpproptech-security.conf;
   ```

3. Confirm the following are blocked (expect `403`):

   ```bash
   curl -i https://api.example.com/.env
   curl -i https://api.example.com/.git/config
   curl -i https://api.example.com/composer.lock
   ```

4. Confirm headers are present:

   ```bash
   curl -sI https://api.example.com/api/ping.php | grep -Ei \
     'x-content-type|x-frame|referrer|permissions|content-security|strict-transport'
   ```

5. Restrict `/api/cron/generate_invoices.php` to the scheduler. The snippet
   allows only localhost by default. If your scheduler is external, replace the
   `allow` lines with its egress IPs.

## PHP

`deploy/php-hardening.ini` is copied to
`/usr/local/etc/php/conf.d/99-security.ini`. Verify with:

```bash
php -i | grep -E 'expose_php|display_errors|allow_url_include'
```

## Secrets

- `.env` is excluded from the image (`.dockerignore`) and blocked by nginx.
- Prefer platform-injected environment variables over a `.env` file in
  production. If a file must exist, keep it outside the document root.
- Rotate `JWT_SECRET`, `CRON_SECRET`, and the database/SMTP passwords after
  any suspected exposure. A `JWT_SECRET` change invalidates all tokens
  immediately.

## Database

Run both migrations before the first request:

```bash
mysql -u <user> -p <database> < migrations/2026-11-09_security_hardening.sql
mysql -u <user> -p <database> < migrations/2026-11-09_security_hardening_batch3.sql
```

The batch-3 migration adds `users.token_version`, `revoked_tokens`,
`audit_logs`, append-only triggers and password-reset indexes. Existing JWTs
do not carry `ver`/`jti`, so everyone is signed out once after deployment.

Grant the application user only the privileges it needs. Do **not** grant
`UPDATE` or `DELETE` on `audit_logs`; the migration already adds triggers that
reject both, but least privilege is the second lock on the same door.
