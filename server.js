const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const SESSION_SECRET = process.env.SESSION_SECRET || "please-change-this-long-random-secret";

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  name: "vip_panel_sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, "public")));

const users = new Map();
let nextId = 1;
const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);

function safeUser(u) {
  return { id: u.id, name: u.name, username: u.username, status: u.status, credit: u.credit, createdAt: u.createdAt, transactions: u.transactions };
}
function requireUser(req, res, next) {
  if (!req.session.userId || !users.has(req.session.userId)) return res.status(401).json({ error: "براہ کرم پہلے لاگ اِن کریں۔" });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") return res.status(401).json({ error: "صرف ایڈمن رسائی حاصل کر سکتا ہے۔" });
  next();
}
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.post("/api/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 2 || username.length < 3 || password.length < 8) {
    return res.status(400).json({ error: "نام، کم از کم 3 حروف کا یوزر نیم، اور کم از کم 8 حرف کا پاس ورڈ درج کریں۔" });
  }
  if (!/^[a-z0-9_.-]+$/.test(username)) return res.status(400).json({ error: "یوزر نیم میں صرف انگریزی حروف، نمبر، نقطہ، ڈیش یا انڈر اسکور استعمال کریں۔" });
  if (username === ADMIN_USERNAME.toLowerCase() || [...users.values()].some(u => u.username === username)) {
    return res.status(409).json({ error: "یہ یوزر نیم پہلے سے استعمال ہو رہا ہے۔" });
  }
  const user = { id: nextId++, name, username, passwordHash: await bcrypt.hash(password, 10), status: "pending", credit: 0, createdAt: new Date().toISOString(), transactions: [] };
  users.set(user.id, user);
  res.json({ message: "اکاؤنٹ کی درخواست جمع ہو گئی ہے۔ ایڈمن کی منظوری کے بعد لاگ اِن کریں۔" });
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = [...users.values()].find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: "یوزر نیم یا پاس ورڈ درست نہیں۔" });
  if (user.status !== "approved") return res.status(403).json({ error: user.status === "pending" ? "آپ کا اکاؤنٹ ایڈمن کی منظوری کا منتظر ہے۔" : "آپ کا اکاؤنٹ غیر فعال ہے۔ ایڈمن سے رابطہ کریں۔" });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "لاگ اِن نہیں ہو سکا۔ دوبارہ کوشش کریں۔" });
    req.session.userId = user.id;
    req.session.role = "user";
    res.json({ message: "لاگ اِن کامیاب ہے۔", user: safeUser(user) });
  });
});

app.post("/api/admin/login", async (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  if (username !== ADMIN_USERNAME || !(await bcrypt.compare(password, adminHash))) return res.status(401).json({ error: "ایڈمن لاگ اِن کی تفصیل درست نہیں۔" });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "لاگ اِن نہیں ہو سکا۔" });
    req.session.role = "admin";
    res.json({ message: "ایڈمن لاگ اِن کامیاب ہے۔" });
  });
});
app.get("/api/me", requireUser, (req, res) => res.json({ user: safeUser(users.get(req.session.userId)) }));
app.get("/api/admin/users", requireAdmin, (_, res) => res.json({ users: [...users.values()].map(safeUser) }));
app.post("/api/admin/users/:id/approve", requireAdmin, (req, res) => {
  const user = users.get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: "اکاؤنٹ نہیں ملا۔" });
  user.status = "approved";
  res.json({ message: `${user.username} کا اکاؤنٹ منظور ہو گیا۔` });
});
app.post("/api/admin/users/:id/disable", requireAdmin, (req, res) => {
  const user = users.get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: "اکاؤنٹ نہیں ملا۔" });
  user.status = "disabled";
  res.json({ message: "اکاؤنٹ غیر فعال کر دیا گیا۔" });
});
app.post("/api/admin/users/:id/credit", requireAdmin, (req, res) => {
  const user = users.get(Number(req.params.id));
  const amount = Number(req.body.amount);
  const note = String(req.body.note || "ایڈمن ایڈجسٹمنٹ").trim().slice(0, 120);
  if (!user) return res.status(404).json({ error: "اکاؤنٹ نہیں ملا۔" });
  if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 10000000) return res.status(400).json({ error: "درست رقم درج کریں۔" });
  if (user.credit + amount < 0) return res.status(400).json({ error: "بیلنس صفر سے کم نہیں ہو سکتا۔" });
  user.credit = Math.round((user.credit + amount) * 100) / 100;
  user.transactions.unshift({ amount, note, at: new Date().toISOString() });
  res.json({ message: `بیلنس اپ ڈیٹ ہو گیا۔ نیا بیلنس: ${user.credit}` });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ message: "لاگ آؤٹ ہو گیا۔" })));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "سرور میں مسئلہ پیش آیا۔" }); });
app.listen(PORT, () => console.log(`VIP Panel running on port ${PORT}`));
