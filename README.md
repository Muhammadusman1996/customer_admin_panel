# VIP Customer + Admin Panel

A starter Node.js website with a glossy premium dark navy, champagne-gold and teal design.

## Features
- Customer registration and login
- New customer accounts wait for admin approval
- Admin dashboard to approve/disable accounts
- Admin can add or subtract customer credit with a note
- Member dashboard shows balance and transaction history
- Passwords hashed with bcryptjs; session cookies are HTTP-only

## Important limitations
This starter stores accounts and credit in memory. **All accounts and credit history are lost whenever the server restarts or redeploys.** Do not use for real money or production until persistent database storage, backups, CSRF protection, rate limiting, HTTPS, and audit controls are configured. Credit is an internal demo ledger, not a payment processor. Do not promise guaranteed returns.

## Run locally
1. Install Node.js 18 or newer.
2. In this folder run `npm install`.
3. Set environment variables, especially a strong admin password and session secret.
4. Run `npm start`.
5. Open `http://localhost:3000` for customers and `http://localhost:3000/admin` for admin.

Example environment variables:
- `ADMIN_USERNAME=admin`
- `ADMIN_PASSWORD=Use-A-Long-Unique-Password`
- `SESSION_SECRET=replace-with-a-long-random-secret`
- `NODE_ENV=production` (on production hosting with HTTPS)

The default admin password is `ChangeMe123!` only for local testing. Change it before deployment. Never publish the default credentials.

## Deploy to Render
Create a Web Service from this folder/repository. Build command: `npm install`. Start command: `npm start`. Add `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `SESSION_SECRET` as environment variables in the service dashboard. This project currently has no persistent database; configure one before real use.
