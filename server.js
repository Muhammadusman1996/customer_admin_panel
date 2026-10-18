const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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
      email TEXT NOT NULL UNIQUE,
      username VARCHAR(30) UNIQUE,
      password_hash TEXT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected')),
      credits BIGINT NOT NULL DEFAULT 0 CHECK (credits >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
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

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'royal_admin_session',
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
  return res.status(401).json({ error: 'Please log in as admin.' });
}

function requireMember(req, res, next) {
  if (req.session?.memberId) return next();
  return res.status(401).json({ error: 'Please log in first.' });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.get('/api/session', (req, res) => {
  res.json({ authenticated: !!req.session?.isAdmin });
});

app.post('/api/register', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 60) {
    return res.status(400).json({ error: 'Enter your name.' });
  }
  if (!/^[a-z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-30 characters: letters, numbers or underscore.' });
  }
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const existing = await pool.query(
      'SELECT id FROM customers WHERE username=$1 OR email=$2',
      [username]
    );
    if (existing.rowCount) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(`
      INSERT INTO customers (name, email, username, password_hash, status, credits)
      VALUES ($1, $2, $3, $4, 'pending', 0)
      RETURNING id
    `, [name, username, passwordHash]);

    return res.status(201).json({
      ok: true,
      message: 'Account created. Please wait for admin approval.',
      customerId: result.rows[0].id
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    return res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/member/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  try {
    const result = await pool.query(`
      SELECT id, name, username, password_hash, status, credits
      FROM customers WHERE username=$1
    `, [username]);
    const customer = result.rows[0];

    if (!customer || !customer.password_hash ||
        !(await bcrypt.compare(password, customer.password_hash))) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    if (customer.status !== 'approved') {
      return res.status(403).json({
        error: customer.status === 'rejected'
          ? 'Your account was rejected. Contact admin.'
          : 'Your account is waiting for admin approval.'
      });
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Could not create secure session.' });
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
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.get('/api/me', requireMember, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, username, status, credits
      FROM customers WHERE id=$1
    `, [req.session.memberId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Customer not found.' });
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not load customer.' });
  }
});

app.post('/api/member/logout', requireMember, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (email !== ADMIN_EMAIL.toLowerCase() ||
      !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not create secure session.' });
    req.session.isAdmin = true;
    res.json({ ok: true });
  });
});

app.post('/api/logout', requireAdmin, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/summary', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM customers) AS customers,
        (SELECT COUNT(*) FROM customers WHERE status='pending') AS pending,
        (SELECT COUNT(*) FROM customers WHERE status='approved') AS approved,
        (SELECT COUNT(*) FROM packages WHERE active=1) AS packages
    `);
    const row = result.rows[0];
    res.json({
      customers: Number(row.customers),
      pending: Number(row.pending),
      approved: Number(row.approved),
      packages: Number(row.packages)
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not load summary.' });
  }
});

app.get('/api/customers', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, username, status, credits, created_at
      FROM customers ORDER BY id DESC LIMIT 500
    `);
    res.json(result.rows);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not load customers.' });
  }
});

app.post('/api/customers/:id/status', requireAdmin, async (req, res) => {
  const status = String(req.body.status || '');
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }
  try {
    const result = await pool.query(
      'UPDATE customers SET status=$1 WHERE id=$2 RETURNING id',
      [status, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Customer not found.' });
    res.json({ ok: true });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not update customer.' });
  }
});

app.post('/api/customers/:id/credits', requireAdmin, async (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isSafeInteger(amount) || amount < 0 || amount > 100000000) {
    return res.status(400).json({ error: 'Enter a valid non-negative whole number.' });
  }
  try {
    const result = await pool.query(
      'UPDATE customers SET credits=$1 WHERE id=$2 RETURNING id',
      [amount, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Customer not found.' });
    res.json({ ok: true });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not update credits.' });
  }
});

app.get('/api/packages', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, amount, active FROM packages ORDER BY id DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not load packages.' });
  }
});

app.post('/api/packages', requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const amount = Number(req.body.amount);
  if (!name || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) {
    return res.status(400).json({ error: 'Enter a package name and valid amount.' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO packages(name, amount) VALUES($1, $2) RETURNING id',
      [name, amount]
    );
    res.json({ ok: true, id: result.rows[0].id });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not create package.' });
  }
});

app.post('/api/packages/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      UPDATE packages
      SET active = CASE active WHEN 1 THEN 0 ELSE 1 END
      WHERE id=$1 RETURNING id
    `, [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Package not found.' });
    res.json({ ok: true });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Could not update package.' });
  }
});

async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`Royal Member server listening on port ${PORT}`);
  });
}

start().catch(error => {
  console.error('Database initialization failed:', error);
  process.exit(1);
});
