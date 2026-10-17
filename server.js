const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = "ms6033291@gmail.com";
const ADMIN_NAME = "Royal Admin";
const ADMIN_CONTACT = "03021394509";
const ADMIN_CONTACT_2 = "03060001167";
const ADMIN_PASSWORD_HASH = "$2a$10$9NsG5FweXTTzKSqS0vsyFOsH5sFeBO71oiyUsInsiGE2.t/JDd5gi";
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
  console.error('Set ADMIN_EMAIL, ADMIN_PASSWORD_HASH, and SESSION_SECRET in your hosting environment.');
  process.exit(1);
}

const db = new Database(process.env.DB_PATH || 'royal-member.sqlite');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS customers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 credits INTEGER NOT NULL DEFAULT 0 CHECK(credits >= 0),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS packages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 amount INTEGER NOT NULL CHECK(amount > 0),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'royal_admin_session',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 2 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ error: 'Please log in as admin.' });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.get('/api/session', (req, res) => res.json({ authenticated: !!(req.session && req.session.isAdmin) }));
app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (email !== ADMIN_EMAIL.toLowerCase() || !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not create secure session.' });
    req.session.isAdmin = true;
    res.json({ ok: true });
  });
});
app.post('/api/logout', requireAdmin, (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/summary', requireAdmin, (req, res) => {
  const customers = db.prepare('SELECT COUNT(*) AS total FROM customers').get().total;
  const pending = db.prepare("SELECT COUNT(*) AS total FROM customers WHERE status='pending'").get().total;
  const approved = db.prepare("SELECT COUNT(*) AS total FROM customers WHERE status='approved'").get().total;
  const packages = db.prepare('SELECT COUNT(*) AS total FROM packages WHERE active=1').get().total;
  res.json({ customers, pending, approved, packages });
});
app.get('/api/customers', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id,name,email,status,credits,created_at FROM customers ORDER BY id DESC LIMIT 500').all());
});
app.post('/api/customers/:id/status', requireAdmin, (req, res) => {
  const status = String(req.body.status || '');
  if (!['approved','rejected','pending'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  const result = db.prepare('UPDATE customers SET status=? WHERE id=?').run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Customer not found.' });
  res.json({ ok: true });
});
app.post('/api/customers/:id/credits', requireAdmin, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isSafeInteger(amount) || amount < 0 || amount > 100000000) return res.status(400).json({ error: 'Enter a valid non-negative whole number.' });
  const result = db.prepare('UPDATE customers SET credits=? WHERE id=?').run(amount, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Customer not found.' });
  res.json({ ok: true });
});
app.get('/api/packages', requireAdmin, (req, res) => res.json(db.prepare('SELECT id,name,amount,active FROM packages ORDER BY id DESC').all()));
app.post('/api/packages', requireAdmin, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const amount = Number(req.body.amount);
  if (!name || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) return res.status(400).json({ error: 'Enter a package name and valid amount.' });
  const info = db.prepare('INSERT INTO packages(name,amount) VALUES(?,?)').run(name, amount);
  res.json({ ok: true, id: info.lastInsertRowid });
});
app.post('/api/packages/:id/toggle', requireAdmin, (req, res) => {
  const result = db.prepare('UPDATE packages SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Package not found.' });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Royal Member admin listening on port ${PORT}`));
