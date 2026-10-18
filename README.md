# D1 Dashboard (Cloudflare)

Private company dashboard for D1 Appliance Repair. Sign in with email and password; admins add and remove logins at /admin.

Runs on Cloudflare Workers (free plan). Logins are stored in Workers KV (binding D1_STORE).

Settings (Cloudflare dashboard > the Worker > Settings > Variables and Secrets):
- SESSION_SECRET (secret): long random text, 24+ characters. Signs login cookies.
- ADMIN_EMAIL (secret): the first admin login.
- ADMIN_PASSWORD (secret): first-time password for that login. Used once; the owner must then choose a new one.

Files:
- src/worker.js: all the logic (sign in, logins, admin, data).
- views/: the dashboard and admin pages (only served to signed in users).
- data/: the numbers (only served to signed in users).
- public/: the sign in page and files anyone may load (chart library, icon).
