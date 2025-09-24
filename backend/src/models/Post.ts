import { db } from './database';

export interface Post {
  id: number;
  title: string;
  content: string;
  author_id: number;
  is_public: boolean;
  created_at: string;
}

export class PostModel {
  // VULNERABILITY: SQL Injection and Access Control
  static async findById(id: number): Promise<Post | null> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct string interpolation
      const query = `SELECT * FROM posts WHERE id = ${id}`;

      db.get(query, (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row as Post || null);
        }
      });
    });
  }

  // VULNERABILITY: No access control - exposes private posts
  static async getAllPosts(): Promise<Post[]> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Returns all posts regardless of privacy setting
      const query = 'SELECT * FROM posts ORDER BY created_at DESC';

      db.all(query, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows as Post[]);
        }
      });
    });
  }

  // VULNERABILITY: SQL Injection in search
  static async searchPosts(searchTerm: string): Promise<Post[]> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct string interpolation allows SQL injection
      const query = `
        SELECT * FROM posts
        WHERE title LIKE '%${searchTerm}%'
        OR content LIKE '%${searchTerm}%'
        ORDER BY created_at DESC
      `;

      db.all(query, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows as Post[]);
        }
      });
    });
  }

  // VULNERABILITY: No authorization check
  static async createPost(postData: Partial<Post>): Promise<number> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: No validation or authorization
      const query = `
        INSERT INTO posts (title, content, author_id, is_public)
        VALUES ('${postData.title}', '${postData.content}', ${postData.author_id}, ${postData.is_public ? 1 : 0})
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

  // VULNERABILITY: No ownership verification
  static async updatePost(id: number, updates: Partial<Post>): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const setClause = Object.entries(updates)
        .filter(([key]) => key !== 'id' && key !== 'created_at')
        .map(([key, value]) => {
          if (typeof value === 'string') {
            return `${key} = '${value}'`;
          }
          return `${key} = ${value}`;
        })
        .join(', ');

      // VULNERABLE: No authorization check - anyone can update any post
      const query = `UPDATE posts SET ${setClause} WHERE id = ${id}`;

      db.run(query, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes > 0);
        }
      });
    });
  }

  // VULNERABILITY: No ownership verification for deletion
  static async deletePost(id: number): Promise<boolean> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: No authorization check
      const query = `DELETE FROM posts WHERE id = ${id}`;

      db.run(query, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes > 0);
        }
      });
    });
  }

  // VULNERABILITY: Returns posts from any user without permission check
  static async getPostsByUserId(userId: number): Promise<Post[]> {
    return new Promise((resolve, reject) => {
      // VULNERABLE: Direct string interpolation and no access control
      const query = `SELECT * FROM posts WHERE author_id = ${userId} ORDER BY created_at DESC`;

      db.all(query, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows as Post[]);
        }
      });
    });
  }
}