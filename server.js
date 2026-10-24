'use strict';

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

const ADMIN_EMAIL = (
  process.env.ADMIN_EMAIL || 'ms6033291@gmail.com'
).toLowerCase();

const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SESSION_SECRET || !DATABASE_URL || !ADMIN_PASSWORD_HASH) {
  console.error(
    'Missing SESSION_SECRET, DATABASE_URL, or ADMIN_PASSWORD_HASH.'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'disable'
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false }));

// مشترکہ Session Middleware
app.use(session({
  name: 'royal_member_sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(__dirname));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }

  return res.status(401).json({
    error: 'Please log in as admin.'
  });
}

function requireMember(req, res, next) {
  if (req.session && req.session.memberId) {
    return next();
  }

  return res.status(401).json({
    error: 'Please log in first.'
  });
}

// سروس کی قیمتیں صرف سرور سے کنٹرول ہوں گی
const SERVICE_PRICES = Object.freeze({
  'Easypaisa Account Open': 400,
  'Easypaisa PIN Reset': 50,
  'Easypaisa Account Check': 30,
  'Easypaisa Transaction History': 500
});

// ڈیٹا بیس کی تیاری
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_activities (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT REFERENCES customers(id)
        ON DELETE SET NULL,
      activity_name VARCHAR(100) NOT NULL,
      request_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
      status VARCHAR(20) NOT NULL
        CHECK (status IN (
          'SUCCESS', 'NOT FOUND', 'FAILED', 'PENDING'
        )),
      amount BIGINT NOT NULL DEFAULT 0 CHECK (amount >= 0),
      balance_before BIGINT NOT NULL DEFAULT 0
        CHECK (balance_before >= 0),
      balance_after BIGINT NOT NULL DEFAULT 0
        CHECK (balance_after >= 0),
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_customer_activities_member_date
    ON customer_activities(customer_id, created_at DESC)
  `);
}

// سیشن کی حالت
app.get('/api/session', (req, res) => {
  res.json({
    authenticated: !!req.session?.isAdmin
  });
});

// کسٹمر رجسٹریشن
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
      error: 'Username must be 3-30 characters: letters, numbers or underscore.'
    });
  }

  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({
      error: 'Password must be 8-72 characters.'
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO customers
        (name, username, password_hash, status, credits)
      VALUES ($1, $2, $3, 'pending', 0)
      RETURNING id
    `, [name, username, hash]);

    res.status(201).json({
      ok: true,
      message: 'Account created. Please wait for admin approval.',
      customerId: result.rows[0].id
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Username already exists.'
      });
    }

    console.error('Registration error:', error.message);

    res.status(500).json({
      error: 'Could not create account.'
    });
  }
});

// کسٹمر لاگ اِن
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

      req.session.memberId = String(customer.id);

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

// موجودہ کسٹمر اور اس کی حالیہ سرگرمیاں
app.get('/api/me', requireMember, async (req, res) => {
  try {
    const customerResult = await pool.query(`
      SELECT id, name, username, status, credits
      FROM customers
      WHERE id = $1
    `, [req.session.memberId]);

    const customer = customerResult.rows[0];

    if (!customer) {
      return res.status(404).json({
        error: 'Customer not found.'
      });
    }

    const activitiesResult = await pool.query(`
      SELECT request_id, activity_name, status, amount,
             balance_before, balance_after, details, created_at
      FROM customer_activities
      WHERE customer_id = $1
      ORDER BY created_at DESC
      LIMIT 20
    `, [req.session.memberId]);

    res.json({
      user: customer,
      transactions: activitiesResult.rows
    });
  } catch (error) {
    console.error('Customer lookup error:', error.message);

    res.status(500).json({
      error: 'Could not load customer.'
    });
  }
});

// سروس کی درخواست، بیلنس کی کٹوتی اور رسید
// بیرونی سروس API منسلک ہونے تک اسٹیٹس PENDING رہے گا۔
app.post('/api/member/activities', requireMember, async (req, res) => {
  const activityName = String(
    req.body.activityName || ''
  ).trim();

  const price = SERVICE_PRICES[activityName];

  if (!price) {
    return res.status(400).json({
      error: 'Unknown service. Please choose an available service.'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const customerResult = await client.query(`
      SELECT id, username, credits, status
      FROM customers
      WHERE id = $1
      FOR UPDATE
    `, [req.session.memberId]);

    const customer = customerResult.rows[0];

    if (!customer || customer.status !== 'approved') {
      await client.query('ROLLBACK');

      return res.status(403).json({
        error: 'Approved member account required.'
      });
    }

    const before = Number(customer.credits);

    if (!Number.isSafeInteger(before) || before < price) {
      await client.query('ROLLBACK');

      return res.status(402).json({
        error: `Insufficient balance. This service costs Rs. ${price}.`,
        required: price,
        balance: before
      });
    }

    const after = before - price;

    await client.query(
      'UPDATE customers SET credits = $1 WHERE id = $2',
      [after, customer.id]
    );

    const receiptResult = await client.query(`
      INSERT INTO customer_activities
        (customer_id, activity_name, status, amount,
         balance_before, balance_after, details)
      VALUES ($1, $2, 'PENDING', $3, $4, $5, $6::jsonb)
      RETURNING request_id, activity_name, status, amount,
                balance_before, balance_after, details, created_at
    `, [
      customer.id,
      activityName,
      price,
      before,
      after,
      JSON.stringify({
        message: 'Request received. Provider result is pending.',
        username: customer.username
      })
    ]);

    await client.query('COMMIT');

    res.status(201).json({
      ok: true,
      receipt: receiptResult.rows[0],
      user: {
        credits: after
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');

    console.error('Activity request error:', error.message);

    res.status(500).json({
      error: 'Could not process service request.'
    });
  } finally {
    client.release();
  }
});

// کسٹمر کی اپنی ایکٹیویٹی ہسٹری
app.get('/api/member/activities', requireMember, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT request_id, activity_name, status, amount,
             balance_before, balance_after, details, created_at
      FROM customer_activities
      WHERE customer_id = $1
      ORDER BY created_at DESC
      LIMIT 100
    `, [req.session.memberId]);

    res.json({
      activities: result.rows
    });
  } catch (error) {
    console.error('Activity history error:', error.message);

    res.status(500).json({
      error: 'Could not load activity history.'
    });
  }
});

// کسٹمر لاگ آؤٹ
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

// ایڈمن لاگ اِن
app.post('/api/login', async (req, res) => {
  const email = String(req.body.email || '')
    .trim()
    .toLowerCase();
  const password = String(req.body.password || '');

  let valid = false;

  try {
    valid =
      email === ADMIN_EMAIL &&
      await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  } catch (_) {
    valid = false;
  }

  if (!valid) {
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

// ایڈمن لاگ آؤٹ
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

// ایڈمن ڈیش بورڈ سمری
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

// ایڈمن: کسٹمر لسٹ
app.get('/api/customers', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, username, status, credits, created_at
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

// ایڈمن: کسٹمر ڈیلیٹ
app.delete('/api/customers/:id', requireAdmin, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(400).json({
      error: 'Invalid customer ID.'
    });
  }

  try {
    const result = await pool.query(
      'DELETE FROM customers WHERE id = $1 RETURNING id',
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Customer account not found.'
      });
    }

    res.json({
      ok: true,
      message: 'Customer account deleted successfully.'
    });
  } catch (error) {
    console.error('Delete customer error:', error.message);

    res.status(500).json({
      error: 'Could not delete customer account.'
    });
  }
});

// ایڈمن: کسٹمر کی منظوری یا مسترد کرنا
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

// ایڈمن: کسٹمر کریڈٹس اپڈیٹ
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

// ایڈمن: پیکیجز کی فہرست
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

// ایڈمن: نیا پیکیج
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

// ایڈمن: پیکیج فعال یا غیر فعال
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

// ایڈمن: حقیقی نتیجے کی تصدیق کے بعد اسٹیٹس اپڈیٹ
app.post(
  '/api/admin/activities/:requestId/status',
  requireAdmin,
  async (req, res) => {
    const status = String(req.body.status || '');
    const message = String(req.body.message || '').slice(0, 500);

    if (!['SUCCESS', 'NOT FOUND', 'FAILED', 'PENDING'].includes(status)) {
      return res.status(400).json({
        error: 'Invalid status.'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(`
        SELECT *
        FROM customer_activities
        WHERE request_id = $1
        FOR UPDATE
      `, [req.params.requestId]);

      const activity = result.rows[0];

      if (!activity) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Activity not found.'
        });
      }

      const wasRefunded = activity.details?.refunded === true;
      const needsRefund =
        ['FAILED', 'NOT FOUND'].includes(status) &&
        !wasRefunded &&
        activity.customer_id &&
        Number(activity.amount) > 0;

      let balanceAfter = Number(activity.balance_after);

      if (needsRefund) {
        const refund = await client.query(`
          UPDATE customers
          SET credits = credits + $1
          WHERE id = $2
          RETURNING credits
        `, [activity.amount, activity.customer_id]);

        if (refund.rowCount) {
          balanceAfter = Number(refund.rows[0].credits);
        }
      }

      const detailsUpdate = {
        message,
        ...(needsRefund ? { refunded: true } : {})
      };

      const updated = await client.query(`
        UPDATE customer_activities
        SET status = $1,
            balance_after = $2,
            details = details || $3::jsonb
        WHERE request_id = $4
        RETURNING request_id, activity_name, status, amount,
                  balance_before, balance_after, details, created_at
      `, [
        status,
        balanceAfter,
        JSON.stringify(detailsUpdate),
        req.params.requestId
      ]);

      await client.query('COMMIT');

      res.json({
        ok: true,
        receipt: updated.rows[0]
      });
    } catch (error) {
      await client.query('ROLLBACK');

      console.error('Activity status update error:', error.message);

      res.status(500).json({
