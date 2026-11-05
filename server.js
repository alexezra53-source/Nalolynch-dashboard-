import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const production = process.env.NODE_ENV === "production";

if (production && (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Set a secure SESSION_SECRET.");
}

fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });

const db = new Database(path.join(__dirname, "data", "portal.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY,
 full_name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT DEFAULT 'client'
);

CREATE TABLE IF NOT EXISTS ledger (
 id INTEGER PRIMARY KEY,
 user_id INTEGER NOT NULL,
 amount_cents INTEGER NOT NULL,
 entry_type TEXT NOT NULL,
 memo TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS withdrawal_requests (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 amount_cents INTEGER NOT NULL,
 recipient_name TEXT NOT NULL,
 bank_name TEXT NOT NULL,
 account_last4 TEXT NOT NULL,
 country TEXT NOT NULL,
 status TEXT DEFAULT 'received',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const Store = SQLiteStoreFactory(session);

app.use(helmet());
app.use(express.json());

app.use(session({
 store: new Store({
   db: "sessions.sqlite",
   dir: path.join(__dirname, "data")
 }),
 name: "account.sid",
 secret: process.env.SESSION_SECRET ||
   crypto.randomBytes(48).toString("hex"),
 resave: false,
 saveUninitialized: false,
 cookie: {
   httpOnly: true,
   sameSite: "strict",
   secure: production,
   maxAge: 30 * 60 * 1000
 }
}));

app.use("/api", rateLimit({
 windowMs: 15 * 60 * 1000,
 limit: 100
}));

app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
 if (!req.session.userId)
   return res.status(401).json({ error: "Please sign in." });
 next();
}

app.get("/api/csrf", (req, res) => {
 req.session.csrf = crypto.randomBytes(24).toString("hex");
 res.json({ csrfToken: req.session.csrf });
});

function csrf(req, res, next) {
 if (req.get("x-csrf-token") !== req.session.csrf)
   return res.status(403).json({ error: "Security token expired." });
 next();
}

app.post("/api/login", csrf, (req, res) => {
 const email = String(req.body.email || "").trim().toLowerCase();
 const password = String(req.body.password || "");

 const user = db.prepare(
   "SELECT id,password_hash FROM users WHERE email=?"
 ).get(email);

 if (!user || !bcrypt.compareSync(password, user.password_hash))
   return res.status(401).json({ error: "Invalid login details." });

 req.session.regenerate(err => {
   if (err) return res.status(500).json({ error: "Session error." });
   req.session.userId = user.id;
   req.session.csrf = crypto.randomBytes(24).toString("hex");
   res.json({ ok: true });
 });
});

app.get("/api/me", auth, (req, res) => {
 const user = db.prepare(
   "SELECT id,full_name,email,role FROM users WHERE id=?"
 ).get(req.session.userId);

 const balance = db.prepare(
   "SELECT COALESCE(SUM(amount_cents),0) cents FROM ledger WHERE user_id=?"
 ).get(user.id).cents;

 res.json({ user, balanceCents: balance });
});

app.post("/api/withdrawals", auth, csrf, (req, res) => {
 const amount = Number(req.body.amountCents);
 const recipient = String(req.body.recipientName || "").trim();
 const bank = String(req.body.bankName || "").trim();
 const account = String(req.body.accountNumber || "").replace(/\D/g, "");
 const country = String(req.body.country || "").trim();

 if (!Number.isSafeInteger(amount) || amount <= 0 ||
     !recipient || !bank || account.length < 4 || !country) {
   return res.status(400).json({ error: "Invalid withdrawal details." });
 }

 const balance = db.prepare(
   "SELECT COALESCE(SUM(amount_cents),0) cents FROM ledger WHERE user_id=?"
 ).get(req.session.userId).cents;

 if (amount > balance)
   return res.status(400).json({ error: "Insufficient available balance." });

 const id = "WR-" + crypto.randomBytes(6).toString("hex").toUpperCase();

 db.prepare(`
 INSERT INTO withdrawal_requests
 (id,user_id,amount_cents,recipient_name,bank_name,account_last4,country)
 VALUES (?,?,?,?,?,?,?)
 `).run(
   id, req.session.userId, amount,
   recipient, bank, account.slice(-4), country
 );

 res.status(201).json({
   ok: true,
   requestId: id,
   status: "received",
   message: "Request received for review. No bank transfer has been sent."
 });
});

app.get("*", (req, res) => {
 res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
 console.log(`Portal running on port ${PORT}`);
});
