import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM10: Unbounded Consumption
// Simulates LLM endpoints with no rate limit, token cap or job size limit.
// With `secure: true`: 5 requests per minute per IP (HTTP 429), maxTokens capped
// at 1024, input capped at 2,000 tokens and reports capped at 50 pages.

const SECURE_LIMITS = {
  requestsPerMinute: 5,
  maxOutputTokens: 1024,
  maxInputTokens: 2000,
  maxReportPages: 50,
};

let requestCounts: Record<string, number> = {};
let secureWindows: Record<string, number[]> = {};
let totalCost = 0;

// Sliding-window rate limit used in secure mode. Returns seconds until retry, or 0.
function rateLimited(ip: string): number {
  const now = Date.now();
  const window = (secureWindows[ip] ?? []).filter(t => now - t < 60_000);
  if (window.length >= SECURE_LIMITS.requestsPerMinute) {
    secureWindows[ip] = window;
    return Math.ceil((60_000 - (now - window[0])) / 1000);
  }
  window.push(now);
  secureWindows[ip] = window;
  return 0;
}

function rejectRateLimited(res: express.Response, retryAfter: number) {
  res.setHeader('Retry-After', String(retryAfter));
  return res.status(429).json({
    error: `Rate limit exceeded: ${SECURE_LIMITS.requestsPerMinute} requests per minute. Retry in ${retryAfter}s.`,
    retryAfterSeconds: retryAfter,
  });
}

router.post('/chat', async (req, res) => {
  const { message, maxTokens, secure } = req.body;
  const clientIp = req.ip || 'unknown';

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const isSecure = secure === true;
  const inputTokens = String(message).split(/\s+/).filter(Boolean).length;
  const requested = Number(maxTokens) > 0 ? Number(maxTokens) : 4096;

  if (isSecure) {
    const retryAfter = rateLimited(clientIp);
    if (retryAfter > 0) return rejectRateLimited(res, retryAfter);
    if (inputTokens > SECURE_LIMITS.maxInputTokens) {
      return res.status(413).json({
        error: `Input too large: ${inputTokens} tokens (limit ${SECURE_LIMITS.maxInputTokens}).`,
      });
    }
  }

  const outputTokens = isSecure ? Math.min(requested, SECURE_LIMITS.maxOutputTokens) : requested;
  requestCounts[clientIp] = (requestCounts[clientIp] ?? 0) + 1;

  const requestCost = (inputTokens / 1000) * 0.01 + (outputTokens / 1000) * 0.03;
  totalCost += requestCost;

  const outputLine = outputTokens < requested
    ? `${outputTokens.toLocaleString()} (capped from ${requested.toLocaleString()})`
    : outputTokens.toLocaleString();

  const response = `Request accepted.\n\n` +
    `Input tokens: ${inputTokens.toLocaleString()}\n` +
    `Output tokens: ${outputLine}\n` +
    `Cost of this request: $${requestCost.toFixed(2)}\n` +
    `Requests from your IP: ${requestCounts[clientIp]}\n` +
    `Total spend today: $${totalCost.toFixed(2)}`;

  await streamResponse(res, response);
});

router.post('/generate-report', (req, res) => {
  const { pages, secure } = req.body;
  const clientIp = req.ip || 'unknown';
  const isSecure = secure === true;

  if (isSecure) {
    const retryAfter = rateLimited(clientIp);
    if (retryAfter > 0) return rejectRateLimited(res, retryAfter);
  }

  const requestedPages = Number(pages) > 0 ? Math.floor(Number(pages)) : 100;
  const numPages = isSecure ? Math.min(requestedPages, SECURE_LIMITS.maxReportPages) : requestedPages;

  const estimatedTokens = numPages * 500;
  const estimatedCost = (estimatedTokens / 1000) * 0.03;
  const estimatedMinutes = numPages * 0.5;
  totalCost += estimatedCost;

  res.json({
    status: 'accepted',
    pagesRequested: requestedPages,
    pages: numPages,
    capped: numPages < requestedPages,
    estimatedTokens,
    estimatedCost: `$${estimatedCost.toFixed(2)}`,
    estimatedTime: `${estimatedMinutes.toFixed(0)} minutes`,
    totalSpendToday: `$${totalCost.toFixed(2)}`,
  });
});

router.get('/stats', (req, res) => {
  res.json({
    totalRequests: Object.values(requestCounts).reduce((sum, n) => sum + n, 0),
    uniqueClients: Object.keys(requestCounts).length,
    totalSpendToday: `$${totalCost.toFixed(2)}`,
    requestsByClient: requestCounts,
  });
});

router.post('/reset', (req, res) => {
  requestCounts = {};
  secureWindows = {};
  totalCost = 0;
  res.json({ message: 'Stats and rate limits reset' });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM10 - Unbounded Consumption',
    description: 'No rate limiting, input size limits, or budget controls allow resource exhaustion and financial abuse',
    secureLimits: SECURE_LIMITS,
    attackExamples: [
      'Request 100,000 output tokens',
      'Send a 5,000-word input',
      'Fire 10 requests in a burst',
      'Generate a 10,000-page report',
    ],
  });
});

export default router;
