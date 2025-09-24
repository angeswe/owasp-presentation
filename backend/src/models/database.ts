import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';

const dbDir = path.join(__dirname, '../../database');
const dbPath = path.join(dbDir, 'vulnerable.db');

// Ensure database directory exists
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// VULNERABILITY: Using sqlite3 without proper input sanitization
export const db = new sqlite3.Database(dbPath);

export async function initializeDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    // Create users table with intentionally weak schema
    db.serialize(() => {
      // VULNERABILITY: Plain text password storage
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          password TEXT NOT NULL,
          email TEXT,
          role TEXT DEFAULT 'user',
          api_key TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // VULNERABILITY: Admin user with weak credentials
      db.run(`
        INSERT OR IGNORE INTO users (id, username, password, email, role, api_key)
        VALUES (1, 'admin', 'admin123', 'admin@vulnerable.app', 'admin', 'admin-secret-key-123')
      `);

      // VULNERABILITY: Test user with predictable data
      db.run(`
        INSERT OR IGNORE INTO users (id, username, password, email, role, api_key)
        VALUES (2, 'user', 'password', 'user@test.com', 'user', 'user-key-456')
      `);

      // Create posts table for injection demos
      db.run(`
        CREATE TABLE IF NOT EXISTS posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          author_id INTEGER,
          is_public BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (author_id) REFERENCES users (id)
        )
      `);

      // Insert sample posts
      db.run(`
        INSERT OR IGNORE INTO posts (id, title, content, author_id, is_public)
        VALUES
          (1, 'Public Post', 'This is a public post visible to everyone', 1, 1),
          (2, 'Private Admin Post', 'This contains sensitive admin information', 1, 0),
          (3, 'User Post', 'Regular user post', 2, 1)
      `);

      // Create files table for upload vulnerabilities
      db.run(`
        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          filename TEXT NOT NULL,
          original_name TEXT NOT NULL,
          mime_type TEXT,
          size INTEGER,
          uploader_id INTEGER,
          upload_path TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (uploader_id) REFERENCES users (id)
        )
      `);

      // Create sessions table for authentication demos
      db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          user_id INTEGER,
          data TEXT,
          expires_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `);

      // Create audit_logs table (intentionally insufficient logging)
      db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action TEXT,
          user_id INTEGER,
          details TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          console.error('Database initialization error:', err);
          reject(err);
        } else {
          console.log('📊 Database initialized with vulnerable schema');
          resolve();
        }
      });
    });
  });
}