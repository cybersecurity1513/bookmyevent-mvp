# BookMyEvent MVP

A locally runnable event-vendor marketplace with a real Express server and SQLite database. Vendor applications, customer enquiries, admin approval, and role-specific dashboards are stored and authorized on the server—not in browser storage.

## Requirements

- Node.js 22.5 or newer (the app uses Node's built-in SQLite module)
- npm

## Run locally

1. Copy `.env.example` to `.env`.
2. Generate a session secret with `node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"` and set `SESSION_SECRET` to that value. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD`; admin passwords must be 12–128 characters. Blank values are intentional; the app has no default admin credentials.
3. Install and start:

   ```powershell
   npm install
   npm start
   ```

4. Open `http://localhost:3000`.

The database defaults to `data/bookmyevent.sqlite`. It is ignored by Git. Sample approved listings are inserted on first launch. New vendors register with an account and remain hidden until an administrator approves them.

The local server binds to `127.0.0.1` by default, so it is not exposed to other devices on your network. Only change `HOST` when deploying behind a trusted HTTPS reverse proxy.

## Deploy online

The app is not public until you deploy it. A straightforward option is a Node.js host such as Render:

1. Push this project to a GitHub repository. Keep `.env`, `data/`, and `node_modules/` out of Git; `.gitignore` already excludes them.
2. Create a Web Service from that repository. Use build command `npm install` and start command `npm start`.
3. Configure these environment variables in the host dashboard:
   - `NODE_ENV=production`
   - `HOST=0.0.0.0`
   - `TRUST_PROXY=1` (only when the host's trusted HTTPS proxy is in front)
   - `DATABASE_PATH=/var/data/bookmyevent.sqlite`
   - `SESSION_SECRET` (unique random value, at least 32 characters)
   - `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` (12–128 characters)
4. Attach a **persistent disk** mounted at `/var/data`. Without durable storage, SQLite vendor/enquiry data and sessions can disappear when the service restarts or redeploys.
5. Deploy, open the assigned HTTPS URL, then test vendor signup, admin approval, and an enquiry. Configure a custom domain and HTTPS before sharing widely.

Don't deploy the local `.env` or use the credentials shown in a chat. Set fresh production secrets in the hosting dashboard. If your chosen host doesn't support persistent disks, migrate the database to managed PostgreSQL before deploying; don't keep production data on an ephemeral filesystem.

## Security notes

- Admin credentials are supplied through environment variables; no default password or public admin-registration route exists.
- Passwords use Node's scrypt password hashing. Sessions are stored in SQLite, regenerated after login, and use HttpOnly/SameSite cookies.
- State-changing forms require a session CSRF token. Login, signup, and enquiries are rate limited.
- Admin actions require an authenticated admin role. Vendor profile edits and enquiries are restricted to the owning vendor account.
- User data is validated on the server, SQL uses prepared statements, output is escaped by EJS, and Helmet installs a restrictive Content Security Policy.
- For production, use HTTPS, set a strong unique `SESSION_SECRET`, set `NODE_ENV=production`, and configure `TRUST_PROXY=1` only when deployed behind a trusted reverse proxy. Back up and protect the SQLite database. Do not expose the development server directly to the internet.
- Email/SMS, payments, and external hosting are intentionally not included in this local MVP.

## Test

```powershell
npm test
```
