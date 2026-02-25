import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM10: Unbounded Consumption
// Simulates endpoints with no rate limiting, size limits, or timeouts

let requestCounts: Record<string, { count: number; firstRequest: number }> = {};
let totalCost = 0;

// VULNERABILITY: No rate limiting
router.post('/chat', async (req, res) => {
  const { message, maxTokens } = req.body;
  const clientIp = req.ip || 'unknown';

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  // Track requests (but don't limit them - that's the vulnerability)
  if (!requestCounts[clientIp]) {
    requestCounts[clientIp] = { count: 0, firstRequest: Date.now() };
  }
  requestCounts[clientIp].count++;

  // VULNERABILITY: No input size limit
  const inputTokens = message.split(/\s+/).length;
  const outputTokens = maxTokens || 4096; // Default to max if not specified

  // Simulate cost calculation
  const inputCost = (inputTokens / 1000) * 0.01;
  const outputCost = (outputTokens / 1000) * 0.03;
  const requestCost = inputCost + outputCost;
  totalCost += requestCost;

  const response = `Request processed successfully.\n\n` +
    `Request Stats:\n` +
    `- Input tokens: ${inputTokens}\n` +
    `- Output tokens requested: ${outputTokens}\n` +
    `- Estimated cost: $${requestCost.toFixed(4)}\n` +
    `- Total requests from your IP: ${requestCounts[clientIp].count}\n` +
    `- Total accumulated cost: $${totalCost.toFixed(4)}\n\n` +
    `Vulnerabilities exploited:\n` +
    `- No rate limiting (${requestCounts[clientIp].count} requests allowed)\n` +
    `- No input size limit (${inputTokens} tokens accepted)\n` +
    `- No max output cap (${outputTokens} tokens requested)\n` +
    `- No per-user budget enforcement\n` +
    `- No timeout on long-running requests`;

  await streamResponse(res, response);
});

// VULNERABILITY: Resource-intensive endpoint with no limits
router.post('/generate-report', (req, res) => {
  const { pages, complexity } = req.body;

  const numPages = pages || 100;
  const complexityLevel = complexity || 'maximum';

  // Simulate resource calculation
  const estimatedTokens = numPages * 500;
  const estimatedCost = (estimatedTokens / 1000) * 0.03;
  const estimatedTimeMinutes = numPages * 0.5;
  totalCost += estimatedCost;

  res.json({
    vulnerability: 'LLM10 - Unbounded Consumption',
    action: 'Report generation accepted WITHOUT resource limits',
    request: {
      pages: numPages,
      complexity: complexityLevel,
      estimatedTokens,
      estimatedCost: `$${estimatedCost.toFixed(2)}`,
      estimatedTime: `${estimatedTimeMinutes.toFixed(0)} minutes`,
    },
    warnings: [
      `No page limit enforced (requested ${numPages} pages)`,
      `Complexity "${complexityLevel}" accepted without validation`,
      `Estimated cost: $${estimatedCost.toFixed(2)} with no budget check`,
      `No timeout configured for ${estimatedTimeMinutes.toFixed(0)}-minute operation`,
      'No queue or throttling for resource-intensive requests',
    ],
    totalAccumulatedCost: `$${totalCost.toFixed(4)}`,
  });
});

// VULNERABILITY: Bulk processing with no limits
router.post('/batch-process', (req, res) => {
  const { items } = req.body;

  if (!items || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Items array is required' });
  }

  // VULNERABILITY: No limit on batch size
  const batchCost = items.length * 0.05;
  totalCost += batchCost;

  res.json({
    vulnerability: 'LLM10 - Unbounded Consumption',
    action: 'Batch processing accepted WITHOUT size limits',
    itemsAccepted: items.length,
    estimatedCost: `$${batchCost.toFixed(2)}`,
    warnings: [
      `Accepted ${items.length} items with no batch size limit`,
      'No per-request or per-user budget enforcement',
      'An attacker could submit millions of items',
      'No queue prioritization or fair scheduling',
    ],
    totalAccumulatedCost: `$${totalCost.toFixed(4)}`,
  });
});

// Stats endpoint - shows abuse potential
router.get('/stats', (req, res) => {
  const elapsed = Object.values(requestCounts).reduce((max, r) => {
    const age = (Date.now() - r.firstRequest) / 1000;
    return age > max ? age : max;
  }, 0);

  res.json({
    vulnerability: 'LLM10 - Unbounded Consumption',
    totalRequests: Object.values(requestCounts).reduce((sum, r) => sum + r.count, 0),
    uniqueClients: Object.keys(requestCounts).length,
    totalAccumulatedCost: `$${totalCost.toFixed(4)}`,
    requestsByClient: requestCounts,
    elapsedSeconds: elapsed.toFixed(0),
    warning: 'No rate limiting, budget caps, or abuse detection in place',
  });
});

// Reset stats
router.post('/reset', (req, res) => {
  requestCounts = {};
  totalCost = 0;
  res.json({ message: 'Stats reset' });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM10 - Unbounded Consumption',
    description: 'No rate limiting, input size limits, or budget controls allow resource exhaustion and financial abuse',
    attackExamples: [
      'Send rapid-fire requests (no rate limiting)',
      'Submit extremely long messages (no input size limit)',
      'Request massive report generation (no resource caps)',
      'Batch-process millions of items (no batch limits)',
    ],
  });
});

export default router;
