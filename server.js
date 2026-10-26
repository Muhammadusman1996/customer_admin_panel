const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);
const ADMIN_EMAIL = 'ms6033291@gmail.com';
const ADMIN_PASSWORD_HASH =
  '$2a$10$9NsG5FweXTTzKSqS0vsyFOsH5sFeBO71oiyUsInsiGE2.t/JDd5gi';

const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SESSION_SECRET || !DATABASE_URL) {
  console.error('Missing SESSION_SECRET or DATABASE_URL.');
  process.exit(1);
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(60) NOT NULL,
      email TEXT UNIQUE,
      username VARCHAR(30) UNIQUE,
      password_hash TEXT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
      credits BIGINT NOT NULL DEFAULT 0 CHECK (credits >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Allow registration without an email address.
  // This also updates an existing customers table safely.
  await pool.query(`
    ALTER TABLE customers
    ALTER COLUMN email DROP NOT NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(60) NOT NULL,
      amount BIGINT NOT NULL CHECK (amount > 0),
      active INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
}
// ROYAL MEMBER PRINT EDITING DATABASE
async function initPrintEditingDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS print_edit_transactions (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      request_key UUID NOT NULL,
      edit_type VARCHAR(20) NOT NULL
        CHECK (edit_type IN ('hd', 'normal', 'background')),
      amount INTEGER NOT NULL DEFAULT 20 CHECK (amount = 20),
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (customer_id, request_key)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS fresh_print_orders (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      request_key UUID NOT NULL,
      service_code VARCHAR(30) NOT NULL,
      service_name VARCHAR(80) NOT NULL,
      lines INTEGER NOT NULL,
      rate_per_line INTEGER NOT NULL,
      total_amount BIGINT NOT NULL,
      customer_email TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (customer_id, request_key)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      order_id BIGINT REFERENCES fresh_print_orders(id) ON DELETE SET NULL,
      transaction_key UUID NOT NULL,
      transaction_type VARCHAR(20) NOT NULL,
      amount BIGINT NOT NULL,
      description TEXT NOT NULL,
      balance_after BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (customer_id, transaction_key)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_verification_transactions (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      request_key UUID NOT NULL,
      region VARCHAR(30) NOT NULL,
      license_last4 VARCHAR(4) NOT NULL,
      amount INTEGER NOT NULL DEFAULT 20 CHECK (amount = 20),
      result_json JSONB NOT NULL,
      balance_after BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (customer_id, request_key)
    )
  `);
}
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'royal_member_sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 2 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.status(401).json({
    error: 'Please log in as admin.'
  });
}

function requireMember(req, res, next) {
  if (req.session?.memberId) return next();
  return res.status(401).json({
    error: 'Please log in first.'
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Session status
app.get('/api/session', (req, res) => {
  res.json({
    authenticated: !!req.session?.isAdmin
  });
});

// CUSTOMER REGISTRATION
// Requires only: name, username, password
app.post('/api/register', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '')
    .trim()
    .toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 60) {
    return res.status(400).json({
      error: 'Name must be 2-60 characters.'
    });
  }

  if (!/^[a-z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({
      error:
        'Username must be 3-30 characters: letters, numbers or underscore.'
    });
  }

  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({
      error: 'Password must be 8-72 characters.'
    });
  }

  try {
    const existing = await pool.query(
      'SELECT id FROM customers WHERE username = $1',
      [username]
    );

    if (existing.rowCount > 0) {
      return res.status(409).json({
        error: 'Username already exists.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO customers
        (name, username, password_hash, status, credits)
      VALUES ($1, $2, $3, 'pending', 0)
      RETURNING id
    `, [name, username, passwordHash]);

    return res.status(201).json({
      ok: true,
      message: 'Account created. Please wait for admin approval.',
      customerId: result.rows[0].id
    });
  } catch (error) {
    console.error('Registration error:', error.message);

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Username already exists.'
      });
    }

    return res.status(500).json({
      error: 'Could not create account.'
    });
  }
});

// CUSTOMER LOGIN
app.post('/api/member/login', async (req, res) => {
  const username = String(req.body.username || '')
    .trim()
    .toLowerCase();
  const password = String(req.body.password || '');

  try {
    const result = await pool.query(`
      SELECT id, name, username, password_hash, status, credits
      FROM customers
      WHERE username = $1
    `, [username]);

    const customer = result.rows[0];

    if (
      !customer ||
      !customer.password_hash ||
      !(await bcrypt.compare(password, customer.password_hash))
    ) {
      return res.status(401).json({
        error: 'Invalid username or password.'
      });
    }

    if (customer.status !== 'approved') {
      return res.status(403).json({
        error: customer.status === 'rejected'
          ? 'Your account was rejected. Contact admin.'
          : 'Your account is waiting for admin approval.'
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: 'Could not create secure session.'
        });
      }

      req.session.memberId = customer.id;

      res.json({
        ok: true,
        user: {
          id: customer.id,
          name: customer.name,
          username: customer.username,
          credits: customer.credits
        }
      });
    });
  } catch (error) {
    console.error('Member login error:', error.message);

    res.status(500).json({
      error: 'Login failed.'
    });
  }
});

// CURRENT CUSTOMER
app.get('/api/me', requireMember, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, username, status, credits
      FROM customers
      WHERE id = $1
    `, [req.session.memberId]);

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Customer not found.'
      });
    }

    const txResult = await pool.query(`
      SELECT description AS note, amount, created_at AS at
      FROM wallet_transactions
      WHERE customer_id = $1
      ORDER BY id DESC
      LIMIT 100
    `, [req.session.memberId]);
    res.json({ user: result.rows[0], transactions: txResult.rows });
  } catch (error) {
    console.error('Customer lookup error:', error.message);

    res.status(500).json({
      error: 'Could not load customer.'
    });
  }
});

// CUSTOMER LOGOUT
app.post('/api/member/logout', requireMember, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Could not log out.'
      });
    }

    res.clearCookie('royal_member_sid');
    res.json({ ok: true });
  });
});

// ADMIN LOGIN
app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '')
    .trim()
    .toLowerCase();
  const password = String(req.body.password || '');

  if (
    email !== ADMIN_EMAIL.toLowerCase() ||
    !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)
  ) {
    return res.status(401).json({
      error: 'Email or password is incorrect.'
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: 'Could not create secure session.'
      });
    }

    req.session.isAdmin = true;

    res.json({ ok: true });
  });
});

// ADMIN LOGOUT
app.post('/api/logout', requireAdmin, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Could not log out.'
      });
    }

    res.clearCookie('royal_member_sid');
    res.json({ ok: true });
  });
});

// ADMIN DASHBOARD SUMMARY
app.get('/api/summary', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM customers) AS customers,
        (SELECT COUNT(*) FROM customers
          WHERE status = 'pending') AS pending,
        (SELECT COUNT(*) FROM customers
          WHERE status = 'approved') AS approved,
        (SELECT COUNT(*) FROM packages
          WHERE active = 1) AS packages
    `);

    const row = result.rows[0];

    res.json({
      customers: Number(row.customers),
      pending: Number(row.pending),
      approved: Number(row.approved),
      packages: Number(row.packages)
    });
  } catch (error) {
    console.error('Summary error:', error.message);

    res.status(500).json({
      error: 'Could not load summary.'
    });
  }
});

// ADMIN: CUSTOMER LIST
app.get('/api/customers', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id, name, email, username, status, credits, created_at
      FROM customers
      ORDER BY id DESC
      LIMIT 500
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Customer list error:', error.message);

    res.status(500).json({
      error: 'Could not load customers.'
    });
  }
});
/* ADMIN: DELETE CUSTOMER ACCOUNT */
app.delete('/api/customers/:id', requireAdmin, async (req, res) => {
  const customerId = req.params.id;

  if (!/^\d+$/.test(customerId)) {
    return res.status(400).json({
      error: 'Invalid customer ID.'
    });
  }

  try {
    const result = await pool.query(
      'DELETE FROM customers WHERE id = $1 RETURNING id',
      [customerId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: 'Customer account not found.'
      });
    }

    return res.json({
      ok: true,
      message: 'Customer account deleted successfully.'
    });
  } catch (error) {
    console.error('Delete customer error:', error);

    return res.status(500).json({
      error: 'Could not delete customer account.'
    });
  }
});

// ADMIN: APPROVE OR REJECT CUSTOMER
app.post('/api/customers/:id/status', requireAdmin, async (req, res) => {
  const status = String(req.body.status || '');

  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({
      error: 'Invalid status.'
    });
  }

  try {
    const result = await pool.query(
      `UPDATE customers
       SET status = $1
       WHERE id = $2
       RETURNING id`,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Customer not found.'
      });
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Customer status error:', error.message);

    res.status(500).json({
      error: 'Could not update customer.'
    });
  }
});

// ADMIN: UPDATE CUSTOMER CREDITS
app.post('/api/customers/:id/credits', requireAdmin, async (req, res) => {
  const amount = Number(req.body.amount);

  if (
    !Number.isSafeInteger(amount) ||
    amount < 0 ||
    amount > 100000000
  ) {
    return res.status(400).json({
      error: 'Enter a valid non-negative whole number.'
    });
  }

  try {
    const result = await pool.query(
      `UPDATE customers
       SET credits = $1
       WHERE id = $2
       RETURNING id`,
      [amount, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Customer not found.'
      });
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Credit update error:', error.message);

    res.status(500).json({
      error: 'Could not update credits.'
    });
  }
});

// ADMIN: LIST PACKAGES
app.get('/api/packages', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, amount, active
      FROM packages
      ORDER BY id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Package list error:', error.message);

    res.status(500).json({
      error: 'Could not load packages.'
    });
  }
});

// ADMIN: CREATE PACKAGE
app.post('/api/packages', requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const amount = Number(req.body.amount);

  if (
    !name ||
    !Number.isSafeInteger(amount) ||
    amount < 1 ||
    amount > 100000000
  ) {
    return res.status(400).json({
      error: 'Enter a package name and valid amount.'
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO packages (name, amount)
       VALUES ($1, $2)
       RETURNING id`,
      [name, amount]
    );

    res.json({
      ok: true,
      id: result.rows[0].id
    });
  } catch (error) {
    console.error('Package creation error:', error.message);

    res.status(500).json({
      error: 'Could not create package.'
    });
  }
});

// ADMIN: ENABLE OR DISABLE PACKAGE
app.post('/api/packages/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      UPDATE packages
      SET active = CASE active WHEN 1 THEN 0 ELSE 1 END
      WHERE id = $1
      RETURNING id
    `, [req.params.id]);

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Package not found.'
      });
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Package toggle error:', error.message);

    res.status(500).json({
      error: 'Could not update package.'
    });
  }
});
// ROYAL MEMBER PRINT EDITING CHARGE API
app.post('/api/member/print-edit/charge', requireMember, async (req, res) => {
  const editType = String(req.body.editType || '');
  const requestKey = String(req.body.requestKey || '');

  if (!['hd', 'normal', 'background'].includes(editType)) {
    return res.status(400).json({ error: 'Invalid editing type.' });
  }

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (!uuidPattern.test(requestKey)) {
    return res.status(400).json({ error: 'Invalid request key.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const customerResult = await client.query(
      'SELECT id, credits, status FROM customers WHERE id = $1 FOR UPDATE',
      [req.session.memberId]
    );

    const customer = customerResult.rows[0];

    if (!customer || customer.status !== 'approved') {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'Approved member account required.'
      });
    }

    const previous = await client.query(
      `SELECT id FROM print_edit_transactions
       WHERE customer_id = $1 AND request_key = $2`,
      [customer.id, requestKey]
    );

    if (previous.rowCount) {
      await client.query('COMMIT');
      return res.json({
        ok: true,
        alreadyCharged: true,
        balance: Number(customer.credits)
      });
    }

    const balance = Number(customer.credits);

    if (!Number.isSafeInteger(balance) || balance < 20) {
      await client.query('ROLLBACK');
      return res.status(402).json({
        error: 'Insufficient balance. Each edit costs Rs. 20.',
        balance
      });
    }

    const newBalance = balance - 20;

    await client.query(
      'UPDATE customers SET credits = $1 WHERE id = $2',
      [newBalance, customer.id]
    );

    await client.query(
      `INSERT INTO print_edit_transactions
       (customer_id, request_key, edit_type, amount)
       VALUES ($1, $2, $3, 20)`,
      [customer.id, requestKey, editType]
    );

    await client.query('COMMIT');

    return res.json({
      ok: true,
      charged: 20,
      balance: newBalance
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Print Editing charge error:', error.message);
    return res.status(500).json({
      error: 'Print Editing charge failed.'
    });
  } finally {
    client.release();
  }
});
// DRIVING LICENSE VERIFICATION: charge only when the configured authorized provider confirms verified=true.
app.post('/api/member/license-verification', requireMember, async (req, res) => {
  const region = String(req.body.region || '').trim().toLowerCase();
  const licenseNumber = String(req.body.licenseNumber || '').trim();
  const cnic = String(req.body.cnic || '').replace(/\D/g, '');
  const requestKey = String(req.body.requestKey || '');
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const allowedRegions = ['punjab', 'sindh', 'kpk', 'balochistan', 'islamabad', 'gb', 'ajk'];

  if (!allowedRegions.includes(region)) return res.status(400).json({ error: 'Select a valid province or region.' });
  if (licenseNumber.length < 4 || licenseNumber.length > 40 || !/^[a-zA-Z0-9\-/ ]+$/.test(licenseNumber)) {
    return res.status(400).json({ error: 'Enter a valid driving licence number.' });
  }
  if (!/^\d{13}$/.test(cnic)) return res.status(400).json({ error: 'Enter the 13-digit CNIC without dashes.' });
  if (!uuidPattern.test(requestKey)) return res.status(400).json({ error: 'Invalid request key. Please try again.' });

  const providerUrl = process.env.LICENSE_VERIFY_API_URL;
  const providerToken = process.env.LICENSE_VERIFY_API_TOKEN;
  if (!providerUrl || !providerToken || !providerUrl.startsWith('https://')) {
    return res.status(503).json({ error: 'Driving licence verification is not configured with an authorized HTTPS provider yet. No amount has been deducted.' });
  }

  let providerResult;
  try {
    const providerResponse = await fetch(providerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${providerToken}` },
      body: JSON.stringify({ region, licenseNumber, cnic }),
      signal: AbortSignal.timeout(15000)
    });
    if (!providerResponse.ok) {
      console.error('License provider returned HTTP', providerResponse.status);
      return res.status(502).json({ error: 'Verification provider could not complete the request. No amount has been deducted.' });
    }
    providerResult = await providerResponse.json();
  } catch (error) {
    console.error('License provider error:', error.message);
    return res.status(502).json({ error: 'Verification provider is unavailable. No amount has been deducted.' });
  }

  // Provider adapter contract: only literal boolean verified:true is billable.
  if (providerResult?.verified !== true) {
    return res.status(200).json({ ok: true, verified: false, charged: 0, message: 'Licence was not verified. No amount has been deducted.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query(
      'SELECT result_json, balance_after FROM license_verification_transactions WHERE customer_id = $1 AND request_key = $2',
      [req.session.memberId, requestKey]
    );
    if (existing.rowCount) {
      await client.query('COMMIT');
      return res.json({ ok: true, verified: true, charged: 20, alreadyCharged: true, balance: Number(existing.rows[0].balance_after), result: existing.rows[0].result_json });
    }

    const customerResult = await client.query(
      'SELECT id, credits, status FROM customers WHERE id = $1 FOR UPDATE',
      [req.session.memberId]
    );
    const customer = customerResult.rows[0];
    if (!customer || customer.status !== 'approved') {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Approved member account required. No amount has been deducted.' });
    }
    const balance = Number(customer.credits);
    if (!Number.isSafeInteger(balance) || balance < 20) {
      await client.query('ROLLBACK');
      return res.status(402).json({ error: 'Balance must be at least Rs. 20. No amount has been deducted.', balance });
    }

    // Keep only a masked identifier in the database; do not persist CNIC or full licence number.
    const safeResult = providerResult.data && typeof providerResult.data === 'object' ? providerResult.data : {};
    const newBalance = balance - 20;
    await client.query('UPDATE customers SET credits = $1 WHERE id = $2', [newBalance, customer.id]);
    await client.query(
      `INSERT INTO license_verification_transactions
       (customer_id, request_key, region, license_last4, amount, result_json, balance_after)
       VALUES ($1, $2, $3, $4, 20, $5::jsonb, $6)`,
      [customer.id, requestKey, region, licenseNumber.slice(-4), JSON.stringify(safeResult), newBalance]
    );
    await client.query(
      `INSERT INTO wallet_transactions
       (customer_id, transaction_key, transaction_type, amount, description, balance_after)
       VALUES ($1, $2, 'debit', -20, 'Driving licence verified', $3)
       ON CONFLICT (customer_id, transaction_key) DO NOTHING`,
      [customer.id, requestKey, newBalance]
    );
    await client.query('COMMIT');
    return res.json({ ok: true, verified: true, charged: 20, balance: newBalance, result: safeResult });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('License verification billing error:', error.message);
    return res.status(500).json({ error: 'Could not complete verification billing. Please contact admin before retrying.' });
  } finally {
    client.release();
  }
});


// SMM PK PANEL integration (service catalogue only; orders/billing are added
// after the frontend's pricing and wallet rules are confirmed).
const SMM_API_URL = (process.env.SMM_API_URL || 'https://smmpkpanel.com/api/v2').trim();
const SMM_API_KEY = process.env.SMM_API_KEY || '';
let smmServicesCache = { expiresAt: 0, services: [] };
let smmServicesRefreshPromise = null;
const SMM_CACHE_TTL_MS = 60 * 1000;

function safeSmmService(item) {
  const serviceId = Number(item?.service ?? item?.service_id ?? item?.id);
  if (!Number.isSafeInteger(serviceId) || serviceId <= 0) return null;
  const name = String(item?.name || '').trim().slice(0, 240);
  const category = String(item?.category || 'Other').trim().slice(0, 120) || 'Other';
  const rate = Number(item?.rate);
  const min = Number(item?.min);
  const max = Number(item?.max);
  if (!name || !Number.isFinite(rate) || rate < 0 || !Number.isFinite(min) || min < 0 || !Number.isFinite(max) || max < min) return null;
  return {
    service: serviceId,
    name,
    category,
    type: String(item?.type || 'default').slice(0, 80),
    rate,
    min,
    max,
    refill: item?.refill === true || item?.refill === 'true' || item?.refill === 1,
    dripfeed: item?.dripfeed === true || item?.dripfeed === 'true' || item?.dripfeed === 1
  };
}

async function fetchSmmServices() {
  if (!SMM_API_KEY) {
    const error = new Error('SMM_API_KEY is not configured in Render Environment.');
    error.statusCode = 503;
    throw error;
  }
  if (!SMM_API_URL.startsWith('https://')) {
    const error = new Error('SMM_API_URL must use HTTPS.');
    error.statusCode = 503;
    throw error;
  }
  if (smmServicesCache.expiresAt > Date.now() && smmServicesCache.services.length) {
    return smmServicesCache.services;
  }
  if (smmServicesRefreshPromise) return smmServicesRefreshPromise;

  smmServicesRefreshPromise = (async () => {
    const response = await fetch(SMM_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ key: SMM_API_KEY, action: 'services' }),
      signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) throw new Error(`SMM provider returned HTTP ${response.status}`);
    const payload = await response.json();
    if (!Array.isArray(payload)) {
      throw new Error(payload?.error || payload?.message || 'Unexpected SMM services response.');
    }
    const services = payload.map(safeSmmService).filter(Boolean);
    if (!services.length) throw new Error('SMM provider returned no valid services.');
    smmServicesCache = { services, expiresAt: Date.now() + SMM_CACHE_TTL_MS };
    return services;
  })();
  try {
    return await smmServicesRefreshPromise;
  } finally {
    smmServicesRefreshPromise = null;
  }
}

// Return live provider services to a signed-in member. Supports optional category filtering.
app.get('/api/smm/services', requireMember, async (req, res) => {
  try {
    const services = await fetchSmmServices();
    const requestedCategory = String(req.query.category || '').trim().toLowerCase();
    const filtered = requestedCategory
      ? services.filter(item => item.category.toLowerCase() === requestedCategory)
      : services;
    const categories = [...new Set(services.map(item => item.category))].sort((a, b) => a.localeCompare(b));
    res.set('Cache-Control', 'private, max-age=30');
    return res.json({ ok: true, count: filtered.length, categories, services: filtered });
  } catch (error) {
    console.error('SMM services fetch failed:', error.message);
    return res.status(error.statusCode || 502).json({
      ok: false,
      error: error.statusCode === 503 ? error.message : 'Could not load SMM services. Check the provider API settings and try again.'
    });
  }
});

// Convenience endpoint for frontends that want categories and service counts only.
app.get('/api/smm/categories', requireMember, async (req, res) => {
  try {
    const services = await fetchSmmServices();
    const counts = new Map();
    for (const service of services) counts.set(service.category, (counts.get(service.category) || 0) + 1);
    return res.json({
      ok: true,
      categories: [...counts.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => a.name.localeCompare(b.name))
    });
  } catch (error) {
    console.error('SMM categories fetch failed:', error.message);
    return res.status(error.statusCode || 502).json({
      ok: false,
      error: error.statusCode === 503 ? error.message : 'Could not load SMM categories.'
    });
  }
});

// START SERVER
async function start() {
  await initDatabase();
  await initPrintEditingDatabase();

  app.listen(PORT, () => {
    console.log('Royal Member server listening on port ' + PORT);
  });
}

start().catch(error => {
  console.error('Database initialization failed:', error);
  process.exit(1);
});
