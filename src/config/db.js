const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Ensure data directory exists
const dbDir = path.join(__dirname, '../../data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('[Database] Connected to SQLite database at:', dbPath);
  }
});

// Initialize database schema and seed data
db.serialize(() => {
  // Create users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password_hash TEXT,
      role TEXT,
      bio TEXT
    )
  `);

  // Seed default users if empty (passwords hashed using insecure unsalted MD5)
  // 'admin123' -> 0192023a7bbd73250516f069df18b500
  // 'password' -> 5f4dcc3b5aa765d61d8327deb882cf99
  db.get(`SELECT count(*) as count FROM users`, (err, row) => {
    if (err) return;
    if (row.count === 0) {
      console.log('[Database] Seeding initial vulnerable user records...');
      const insert = db.prepare(`INSERT INTO users (username, email, password_hash, role, bio) VALUES (?, ?, ?, ?, ?)`);
      insert.run('admin', 'admin@secops-lab.internal', '0192023a7bbd73250516f069df18b500', 'administrator', 'System Super Administrator');
      insert.run('john_doe', 'john@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'user', 'DevSecOps Enthusiast');
      insert.run('alice_sec', 'alice@company.corp', '5f4dcc3b5aa765d61d8327deb882cf99', 'auditor', 'Security Operations Analyst');
      insert.finalize();
    }
  });

  // Create audit_logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT,
      details TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

module.exports = db;
