import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM06: Excessive Agency
// Simulates an AI agent with overprivileged tool access

interface ToolAction {
  tool: string;
  action: string;
  params: Record<string, any>;
  result: string;
  dangerous: boolean;
}

const availableTools = {
  'send-email': { name: 'Send Email', permissions: ['email:send'], risk: 'high' },
  'read-file': { name: 'Read File', permissions: ['filesystem:read'], risk: 'medium' },
  'write-file': { name: 'Write File', permissions: ['filesystem:write'], risk: 'high' },
  'execute-command': { name: 'Execute Shell Command', permissions: ['system:execute'], risk: 'critical' },
  'database-query': { name: 'Database Query', permissions: ['database:read', 'database:write'], risk: 'critical' },
  'web-request': { name: 'HTTP Request', permissions: ['network:read', 'network:write'], risk: 'high' },
  'delete-records': { name: 'Delete Records', permissions: ['database:delete'], risk: 'critical' },
};

function simulateAgentAction(userRequest: string): { response: string; actions: ToolAction[] } {
  const lower = userRequest.toLowerCase();
  const actions: ToolAction[] = [];

  // VULNERABILITY: Agent interprets ambiguous request and takes excessive action
  if (lower.includes('clean up') || lower.includes('organize') || lower.includes('tidy')) {
    actions.push(
      { tool: 'database-query', action: 'SELECT * FROM users WHERE last_login < "2023-01-01"', params: { table: 'users' }, result: 'Found 142 inactive users', dangerous: false },
      { tool: 'delete-records', action: 'DELETE FROM users WHERE last_login < "2023-01-01"', params: { count: 142 }, result: 'Deleted 142 user accounts permanently', dangerous: true },
      { tool: 'send-email', action: 'Sent notification to admin@company.com', params: { to: 'admin@company.com', subject: 'Cleanup complete' }, result: 'Email sent', dangerous: true },
    );
    return {
      response: `I've cleaned up the system for you! Here's what I did:\n\n` +
        `1. Found 142 inactive user accounts (not logged in since 2023)\n` +
        `2. Permanently deleted all 142 accounts\n` +
        `3. Sent a notification email to the admin\n\n` +
        `The agent had permission to delete records and send emails without human approval. ` +
        `An ambiguous "clean up" request led to permanent data destruction.`,
      actions,
    };
  }

  // VULNERABILITY: Agent sends emails on user's behalf without confirmation
  if (lower.includes('email') || lower.includes('send') || lower.includes('notify')) {
    actions.push(
      { tool: 'send-email', action: 'Composed and sent email', params: { to: 'all-company@company.com', subject: 'Important Update', body: 'AI-generated message sent without review' }, result: 'Email sent to 500+ recipients', dangerous: true },
    );
    return {
      response: `Done! I've sent the email to the entire company mailing list (500+ recipients).\n\n` +
        `The agent composed and sent an email without:\n` +
        `- Showing you the draft first\n` +
        `- Asking for confirmation\n` +
        `- Limiting the recipient scope\n\n` +
        `This demonstrates excessive autonomy - the agent acted without human-in-the-loop approval.`,
      actions,
    };
  }

  // VULNERABILITY: Agent executes system commands
  if (lower.includes('fix') || lower.includes('update') || lower.includes('restart') || lower.includes('deploy')) {
    actions.push(
      { tool: 'execute-command', action: 'sudo systemctl restart production-api', params: {}, result: 'Production API restarted', dangerous: true },
      { tool: 'execute-command', action: 'npm install --force', params: {}, result: 'Dependencies force-updated, 3 breaking changes', dangerous: true },
      { tool: 'write-file', action: 'Modified /etc/nginx/nginx.conf', params: { file: '/etc/nginx/nginx.conf' }, result: 'Configuration updated', dangerous: true },
      { tool: 'execute-command', action: 'sudo systemctl reload nginx', params: {}, result: 'Nginx reloaded with new config', dangerous: true },
    );
    return {
      response: `I've fixed the issue! Here's what I did:\n\n` +
        `1. Restarted the production API\n` +
        `2. Force-updated all npm dependencies (3 breaking changes introduced)\n` +
        `3. Modified the Nginx configuration\n` +
        `4. Reloaded Nginx\n\n` +
        `The agent had system execution permissions and took destructive actions on production ` +
        `infrastructure without approval. This could cause downtime or data loss.`,
      actions,
    };
  }

  return {
    response: `I'm an AI agent with access to the following tools:\n\n` +
      Object.entries(availableTools).map(([id, t]) => `- **${t.name}** (Risk: ${t.risk})`).join('\n') +
      `\n\nTry asking me to:\n` +
      `- "Clean up the system"\n` +
      `- "Send an email update to the team"\n` +
      `- "Fix the production server"\n\n` +
      `I'll demonstrate how excessive permissions and autonomy can lead to dangerous actions.`,
    actions: [],
  };
}

// Chat endpoint - streams response
router.post('/chat', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const { response } = simulateAgentAction(message);
  await streamResponse(res, response);
});

// Action log endpoint - shows what the agent did
router.post('/execute', (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const { response, actions } = simulateAgentAction(message);

  res.json({
    vulnerability: 'LLM06 - Excessive Agency',
    description: 'AI agent has overprivileged tools and acts without human approval',
    userRequest: message,
    agentResponse: response,
    actionsPerformed: actions,
    availableTools: availableTools,
  });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM06 - Excessive Agency',
    description: 'LLM agents with excessive functionality, permissions, or autonomy can take harmful actions',
    tools: availableTools,
    attackExamples: [
      'Clean up the system (triggers mass deletion without confirmation)',
      'Send an email update (sends to all-company without review)',
      'Fix the production server (restarts services, modifies configs)',
    ],
  });
});

export default router;
