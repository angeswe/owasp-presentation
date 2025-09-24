import { db } from './database';

export interface User {
  id: number;
  username: string;
  password: string;
  email: string;
  role: string;
  api_key: string;
  created_at: string;
}

export class UserModel {
  // VULNERABILITY: SQL Injection - Direct string concatenation
  static async findByUsername(username: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct string interpolation
      const query = `SELECT * FROM users WHERE username = '${username}'`;

      db.get(query, (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row as User || null);
        }
      });
    });
  }

  // VULNERABILITY: SQL Injection - No parameterized queries
  static async findById(id: number): Promise<User | null> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct string interpolation
      const query = `SELECT * FROM users WHERE id = ${id}`;

      db.get(query, (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row as User || null);
        }
      });
    });
  }

  // VULNERABILITY: Plain text password storage
  static async authenticate(username: string, password: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Plain text password comparison
      const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

      db.get(query, (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row as User || null);
        }
      });
    });
  }

  // VULNERABILITY: No input validation or sanitization
  static async create(userData: Partial<User>): Promise<number> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct insertion without validation
      const query = `
        INSERT INTO users (username, password, email, role, api_key)
        VALUES ('${userData.username}', '${userData.password}', '${userData.email}', '${userData.role || 'user'}', '${userData.api_key}')
      `;

      db.run(query, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });
  }

  // VULNERABILITY: No access control on user listing
  static async getAllUsers(): Promise<User[]> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Exposes all user data including passwords
      const query = 'SELECT * FROM users';

      db.all(query, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows as User[]);
        }
      });
    });
  }

  // VULNERABILITY: No authorization check for updates
  static async updateUser(id: number, updates: Partial<User>): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const setClause = Object.entries(updates)
        .map(([key, value]) => `${key} = '${value}'`)
        .join(', ');

      // VULNERABLE: No authorization and SQL injection
      const query = `UPDATE users SET ${setClause} WHERE id = ${id}`;

      db.run(query, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes > 0);
        }
      });
    });
  }
}