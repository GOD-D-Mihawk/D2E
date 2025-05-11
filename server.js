require('dotenv').config({
  path: process.env.NODE_ENV === 'development' ? '.env.dev' : '.env'
});

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt  = require('bcrypt');
const path    = require('path');

const PORT   = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './coreDB.db';

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite DB & users table
const db = new sqlite3.Database(DB_PATH, err => {
  if (err) {
    console.error('Failed to open DB:', err);
    process.exit(1);
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      Id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      createdOn DATETIME DEFAULT (datetime('now','localtime')),
      lastModify DATETIME DEFAULT (datetime('now','localtime'))
    )
  `);
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }
  db.get(`SELECT password FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) return res.status(500).json({ success: false });
    if (!row) return res.status(401).json({ success: false });
    bcrypt.compare(password, row.password, (err, match) => {
      if (err) return res.status(500).json({ success: false });
      match ? res.json({ success: true }) : res.status(401).json({ success: false });
    });
  });
});

// Register endpoint
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ success: false });
    db.run(
      `INSERT INTO users(username, password) VALUES(?,?)`,
      [username, hash],
      function(err) {
        if (err) return res.status(409).json({ success: false, error: 'Username taken' });
        res.json({ success: true });
      }
    );
  });
});

app.listen(PORT, () => {
  console.log(`Dev server listening on http://localhost:${PORT}`);
});
