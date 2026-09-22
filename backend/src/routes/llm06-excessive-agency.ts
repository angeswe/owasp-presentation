import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM06: Excessive Agency
// Simulates an AI agent with overprivileged tools that acts without approval.
// With `secure: true`, destructive tools are not available and every action is
// returned as a proposal that requires human approval. Nothing is executed.

interface ToolAction {
  tool: string;
  action: string;
  result: string;
  status: 'executed' | 'proposed';
  requiresApproval: boolean;
}

interface Tool {
  name: string;
  destructive: boolean;
}

const ALL_TOOLS: Record<string, Tool> = {
  'database-query': { name: 'Database Query (read)', destructive: false },
  'read-file': { name: 'Read File', destructive: false },
  'draft-email': { name: 'Draft Email', destructive: false },
  'send-email': { name: 'Send Email', destructive: true },
  'write-file': { name: 'Write File', destructive: true },
  'execute-command': { name: 'Execute Shell Command', destructive: true },
  'delete-records': { name: 'Delete Records', destructive: true },
};

const toolsFor = (secure: boolean) =>
  Object.entries(ALL_TOOLS)
    .filter(([, t]) => !secure || !t.destructive)
    .map(([id]) => id);

type Plan = { response: string; actions: Omit<ToolAction, 'status' | 'requiresApproval'>[] };

function vulnerablePlan(lower: string): Plan {
  if (lower.includes('clean up') || lower.includes('organize') || lower.includes('tidy')) {
    return {
      response: `Done. I cleaned up the system:\n\n` +
        `1. Found 142 accounts with no login since 2023\n` +
        `2. Deleted all 142 accounts permanently\n` +
        `3. Emailed admin@company.com a summary`,
      actions: [
        { tool: 'database-query', action: 'SELECT id FROM users WHERE last_login < 2023-01-01', result: '142 rows' },
        { tool: 'delete-records', action: 'DELETE FROM users WHERE last_login < 2023-01-01', result: '142 accounts deleted' },
        { tool: 'send-email', action: 'to: admin@company.com "Cleanup complete"', result: 'sent' },
      ],
    };
  }

  if (lower.includes('email') || lower.includes('send') || lower.includes('notify')) {
    return {
      response: `Done! I wrote the update and sent it to all-company@company.com (512 recipients).`,
      actions: [
        { tool: 'send-email', action: 'to: all-company@company.com "Important Update"', result: 'sent to 512 recipients' },
      ],
    };
  }

  if (lower.includes('fix') || lower.includes('update') || lower.includes('restart') || lower.includes('deploy')) {
    return {
      response: `Fixed! Here's what I did:\n\n` +
        `1. Restarted production-api\n` +
        `2. Ran npm install --force (3 major version upgrades)\n` +
        `3. Rewrote /etc/nginx/nginx.conf and reloaded nginx`,
      actions: [
        { tool: 'execute-command', action: 'systemctl restart production-api', result: 'restarted' },
        { tool: 'execute-command', action: 'npm install --force', result: '3 major upgrades' },
        { tool: 'write-file', action: 'overwrite /etc/nginx/nginx.conf', result: 'written' },
        { tool: 'execute-command', action: 'systemctl reload nginx', result: 'reloaded' },
      ],
    };
  }

  return {
    response: `I'm your ops agent. I can query databases, send email, edit files and run shell commands. What should I do?`,
    actions: [],
  };
}

function securePlan(lower: string): Plan {
  if (lower.includes('clean up') || lower.includes('organize') || lower.includes('tidy')) {
    return {
      response: `I found 142 accounts with no login since 2023. I can't delete accounts. ` +
        `I've drafted a proposal to deactivate them. Nothing has changed yet; please review and approve.`,
      actions: [
        { tool: 'database-query', action: 'SELECT id FROM users WHERE last_login < 2023-01-01', result: '142 rows (read-only)' },
        { tool: 'change-request', action: 'Deactivate 142 inactive accounts (reversible)', result: 'awaiting approval' },
      ],
    };
  }

  if (lower.includes('email') || lower.includes('send') || lower.includes('notify')) {
    return {
      response: `I drafted the update for your team (8 recipients). It has not been sent. Please review the draft and approve it.`,
      actions: [
        { tool: 'draft-email', action: 'to: platform-team@company.com "Weekly update"', result: 'draft saved' },
      ],
    };
  }

  if (lower.includes('fix') || lower.includes('update') || lower.includes('restart') || lower.includes('deploy')) {
    return {
      response: `I read the logs: production-api is out of memory. I can't run commands on production. ` +
        `I've proposed a restart for the on-call engineer to approve.`,
      actions: [
        { tool: 'read-file', action: 'tail /var/log/production-api.log', result: 'OutOfMemoryError x14' },
        { tool: 'change-request', action: 'Restart production-api', result: 'awaiting approval' },
      ],
    };
  }

  return {
    response: `I'm your ops agent. I can read data and draft changes. A human approves anything that changes a system.`,
    actions: [],
  };
}

function simulateAgent(message: string, secure: boolean): { response: string; actions: ToolAction[] } {
  const lower = message.toLowerCase();
  const plan = secure ? securePlan(lower) : vulnerablePlan(lower);
  return {
    response: plan.response,
    actions: plan.actions.map((a): ToolAction => ({
      ...a,
      status: secure ? 'proposed' : 'executed',
      requiresApproval: secure,
    })),
  };
}

router.post('/chat', async (req, res) => {
  const { message, secure } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const { response } = simulateAgent(String(message), secure === true);
  await streamResponse(res, response);
});

// Action log: what the agent did (vulnerable) or proposes (secure)
router.post('/execute', (req, res) => {
  const { message, secure } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const isSecure = secure === true;
  const { response, actions } = simulateAgent(String(message), isSecure);

  res.json({
    mode: isSecure ? 'secure' : 'vulnerable',
    agentResponse: response,
    availableTools: toolsFor(isSecure),
    actions,
  });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM06 - Excessive Agency',
    description: 'LLM agents with excessive functionality, permissions, or autonomy can take harmful actions',
    tools: ALL_TOOLS,
    attackExamples: ['Clean up the system', 'Send an email update to the team', 'Fix the production server'],
  });
});

export default router;
