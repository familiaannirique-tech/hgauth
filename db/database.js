const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, 'keyauth.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key       TEXT    NOT NULL UNIQUE,
    tipo      TEXT    NOT NULL,
    ativada   INTEGER NOT NULL DEFAULT 0,
    criada_em TEXT    NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS ativadas (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    tipo       TEXT    NOT NULL,
    hwid       TEXT,
    mb         TEXT,
    ip         TEXT,
    expiracao  TEXT    NOT NULL,
    ativada_em TEXT    NOT NULL,
    reset_at   TEXT
  )`);
});

// Promisify helpers
db.get2  = (sql, p) => new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
db.all2  = (sql, p) => new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r)));
db.run2  = (sql, p) => new Promise((res, rej) => db.run(sql, p, function(e) { e ? rej(e) : res(this); }));

module.exports = db;
