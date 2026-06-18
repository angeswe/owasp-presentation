import express from 'express';

const router = express.Router();

// VULNERABILITY A10: Mishandling of Exceptional Conditions
// NEW category in the OWASP Top 10:2025.
//
// The application does not handle errors safely. When something goes wrong it
// leaks stack traces, absolute file paths, library versions and the failing
// database query straight back to the client. That hands an attacker a free map
// of the system internals — exactly the reconnaissance they need to build a
// targeted exploit. Errors should be logged server-side and a generic, opaque
// message returned to the caller.

// Simulated data-access layer that always raises a detailed, "driver-level" error
// so the demo can show what a leaked DB error looks like.
function runQuery(sql: string, params: Record<string, unknown>): never {
  const offending = Object.values(params)[0];
  const err: any = new Error(`SQLITE_ERROR: near "${offending}": syntax error`);
  err.code = 'SQLITE_ERROR';
  err.sql = sql;
  err.params = params;
  throw err;
}

// VULNERABILITY: arithmetic endpoint with no safe error handling.
// Any bad input throws, and the catch block dumps the whole exception to the client.
router.post('/divide', (req, res) => {
  const { a, b } = req.body || {};
  try {
    if (typeof a !== 'number' || typeof b !== 'number') {
      throw new TypeError(
        `Operands must be numbers, received a=${JSON.stringify(a)} (${typeof a}), ` +
          `b=${JSON.stringify(b)} (${typeof b})`
      );
    }
    if (b === 0) {
      // Force a thrown exception instead of silently returning Infinity.
      throw new RangeError('Division by zero is not permitted');
    }

    res.json({
      vulnerability: 'A10 - Mishandling of Exceptional Conditions',
      description: 'Successful request',
      result: a / b
    });
  } catch (error) {
    const err = error as Error;
    // VULNERABLE: full stack trace, absolute paths and environment dumped to the client.
    res.status(500).json({
      vulnerability: 'A10 - Mishandling of Exceptional Conditions',
      description: 'Unhandled exception leaks internal details to the client',
      error: err.message,
      type: err.name,
      stack: err.stack, // VULNERABLE: reveals source file paths and line numbers
      source_file: __filename, // VULNERABLE: absolute path on the server
      working_directory: process.cwd(),
      node_version: process.version,
      explanation:
        'The stack trace exposes file paths, line numbers and runtime versions that ' +
        'help an attacker fingerprint the stack and build a targeted exploit. Log the ' +
        'error server-side and return a generic message instead.'
    });
  }
});

// VULNERABILITY: database error returned verbatim, exposing the schema and raw query.
router.get('/lookup', (req, res) => {
  const id = req.query.id ?? '';
  // VULNERABLE: query is built and then surfaced in the error response below.
  const sql = `SELECT id, username, email, password_hash, api_key FROM users WHERE id = '${id}'`;
  try {
    const rows = runQuery(sql, { id });
    res.json({ vulnerability: 'A10 - Mishandling of Exceptional Conditions', rows });
  } catch (error) {
    const err = error as any;
    res.status(500).json({
      vulnerability: 'A10 - Mishandling of Exceptional Conditions',
      description: 'Database error returned to the client reveals schema and query',
      error: err.message,
      db_code: err.code,
      failing_query: err.sql, // VULNERABLE: leaks table and column names
      bound_params: err.params,
      stack: err.stack,
      explanation:
        'The raw SQL and driver error disclose the schema — including the ' +
        'password_hash and api_key columns — which directly aids SQL injection and ' +
        'data theft. Return a generic 500 and keep the details in the server log.'
    });
  }
});

// CONTRAST: the same failure handled safely — log internally, return an opaque error.
router.get('/lookup-safe', (req, res) => {
  const id = req.query.id ?? '';
  const sql = 'SELECT id, username FROM users WHERE id = ?';
  try {
    runQuery(sql, { id });
    res.json({ ok: true });
  } catch (error) {
    // SECURE: details stay in the server log; the client gets nothing useful.
    console.error('[A10] /lookup-safe failed:', error);
    res.status(500).json({
      vulnerability: 'A10 - Mishandling of Exceptional Conditions (secure handling)',
      error: 'An unexpected error occurred. Please try again later.',
      reference_id: 'ERR-7F3A21', // a correlation id support can match to the real log entry
      explanation:
        'Identical failure, but no stack trace, query or path is leaked. The attacker ' +
        'learns nothing; an operator can still trace the issue via the reference id.'
    });
  }
});

export default router;
