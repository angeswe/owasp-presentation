import express from 'express';
import { exec } from 'child_process';
import { UserModel } from '../models/User';
import { PostModel } from '../models/Post';
import { db } from '../models/database';

const router = express.Router();

// VULNERABILITY A03: Injection
// This route demonstrates various injection vulnerabilities

// VULNERABILITY: SQL Injection via search
router.get('/search', async (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ error: 'Query parameter is required' });
  }

  try {
    // VULNERABLE: Direct SQL injection
    const posts = await PostModel.searchPosts(query as string);

    res.json({
      vulnerability: 'A03 - Injection (SQL)',
      description: 'SQL injection in search functionality',
      query: query,
      posts: posts,
      explanation: 'Try queries like: \' OR 1=1-- or \'; DROP TABLE posts;--',
      sql_example: `SELECT * FROM posts WHERE title LIKE '%${query}%' OR content LIKE '%${query}%'`
    });
  } catch (error) {
    res.status(500).json({
      error: 'Database error',
      message: (error as Error).message,
      note: 'This error might reveal database structure'
    });
  }
});

// VULNERABILITY: SQL Injection in login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // VULNERABLE: SQL injection in authentication
    const user = await UserModel.findByUsername(username);

    res.json({
      vulnerability: 'A03 - Injection (SQL)',
      description: 'SQL injection in login functionality',
      username: username,
      user: user,
      explanation: 'Try username: admin\' OR \'1\'=\'1\' -- ',
      sql_example: `SELECT * FROM users WHERE username = '${username}'`
    });
  } catch (error) {
    res.status(500).json({
      error: 'Authentication error',
      message: (error as Error).message
    });
  }
});

// VULNERABILITY: Command Injection
router.post('/ping', (req, res) => {
  const { host } = req.body;

  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }

  // VULNERABLE: Command injection
  const command = `ping -c 1 ${host}`;

  exec(command, (error, stdout, stderr) => {
    res.json({
      vulnerability: 'A03 - Injection (Command)',
      description: 'Command injection in ping functionality',
      host: host,
      command: command,
      output: stdout,
      error: stderr,
      explanation: 'Try hosts like: google.com; cat /etc/passwd or google.com && whoami'
    });
  });
});

// VULNERABILITY: NoSQL Injection simulation
router.post('/nosql-login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Simulated NoSQL injection
  // In a real MongoDB scenario, this would be vulnerable to injection

  let query;
  try {
    // VULNERABLE: Direct object construction from user input
    if (typeof username === 'object' || typeof password === 'object') {
      query = { username: username, password: password };
    } else {
      query = { username: username, password: password };
    }

    res.json({
      vulnerability: 'A03 - Injection (NoSQL)',
      description: 'NoSQL injection vulnerability',
      query: query,
      explanation: 'Try JSON payload: {"username": {"$ne": null}, "password": {"$ne": null}}',
      note: 'This simulates MongoDB injection where objects bypass string comparison'
    });
  } catch (error) {
    res.status(500).json({ error: 'Query error' });
  }
});

// VULNERABILITY: LDAP Injection simulation
router.get('/ldap-search', (req, res) => {
  const { filter } = req.query;

  if (!filter) {
    return res.status(400).json({ error: 'Filter is required' });
  }

  // VULNERABLE: LDAP injection simulation
  const ldapQuery = `(&(objectClass=person)(cn=${filter}))`;

  res.json({
    vulnerability: 'A03 - Injection (LDAP)',
    description: 'LDAP injection in user search',
    filter: filter,
    ldap_query: ldapQuery,
    explanation: 'Try filters like: *)(objectClass=*) or john*)((objectClass=*',
    note: 'This simulates LDAP injection that could bypass authentication'
  });
});

// VULNERABILITY: XPath Injection simulation
router.get('/xpath-search', (req, res) => {
  const { username, password } = req.query;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // VULNERABLE: XPath injection
  const xpathQuery = `//user[username/text()='${username}' and password/text()='${password}']`;

  res.json({
    vulnerability: 'A03 - Injection (XPath)',
    description: 'XPath injection in XML-based authentication',
    username: username,
    password: password,
    xpath_query: xpathQuery,
    explanation: 'Try: username=\' or \'1\'=\'1 and password=\' or \'1\'=\'1',
    note: 'XPath injection can bypass authentication in XML-based systems'
  });
});

// VULNERABILITY: Template Injection
router.post('/template', (req, res) => {
  const { name, template } = req.body;

  if (!name || !template) {
    return res.status(400).json({ error: 'Name and template are required' });
  }

  try {
    // VULNERABLE: Server-side template injection
    // This simulates template engines that execute user input
    const result = template.replace(/\{\{name\}\}/g, name);

    // VULNERABLE: Evaluating user input (simulation)
    let evaluated = result;
    if (template.includes('{{') && template.includes('}}')) {
      // Simulate template engine evaluation
      evaluated = `Processed: ${result}`;
    }

    res.json({
      vulnerability: 'A03 - Injection (Template)',
      description: 'Server-side template injection',
      name: name,
      template: template,
      result: evaluated,
      explanation: 'Try template: {{name}} or malicious payloads like {{7*7}}',
      note: 'Template injection can lead to remote code execution'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Template processing error',
      message: (error as Error).message
    });
  }
});

// VULNERABILITY: Expression Language Injection
router.post('/expression', (req, res) => {
  const { expression, value } = req.body;

  if (!expression || value === undefined) {
    return res.status(400).json({ error: 'Expression and value are required' });
  }

  try {
    // VULNERABLE: Evaluating user expressions
    // This simulates expression language injection
    const unsafeExpression = expression.replace(/\{value\}/g, value);

    res.json({
      vulnerability: 'A03 - Injection (Expression Language)',
      description: 'Expression language injection',
      expression: expression,
      value: value,
      unsafe_expression: unsafeExpression,
      explanation: 'Try expressions like: {value} or ${7*7} or ${java.lang.Runtime.getRuntime()}',
      note: 'Expression injection can execute arbitrary code on the server'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Expression evaluation error',
      message: (error as Error).message
    });
  }
});

// VULNERABILITY: Raw SQL execution
router.post('/raw-sql', (req, res) => {
  const { sql } = req.body;

  if (!sql) {
    return res.status(400).json({ error: 'SQL query is required' });
  }

  // VULNERABLE: Direct SQL execution
  db.all(sql, (err, rows) => {
    if (err) {
      res.status(500).json({
        vulnerability: 'A03 - Injection (SQL)',
        description: 'Raw SQL execution',
        sql: sql,
        error: err.message,
        explanation: 'Any SQL query can be executed directly'
      });
    } else {
      res.json({
        vulnerability: 'A03 - Injection (SQL)',
        description: 'Raw SQL execution',
        sql: sql,
        results: rows,
        explanation: 'Try queries like: SELECT * FROM users; or DROP TABLE posts;'
      });
    }
  });
});

export default router;