import express from 'express';

const router = express.Router();

// VULNERABILITY LLM03: Supply Chain Vulnerabilities
// Simulates loading unverified models, plugins, and training data

const MODEL_REGISTRY: Record<string, any> = {
  'gpt-helper-v2': {
    name: 'gpt-helper-v2',
    author: 'verified-ai-corp',
    verified: true,
    downloads: 1250000,
    hash: 'sha256:a1b2c3d4e5f6...',
    description: 'General purpose language model',
  },
  'finance-llm-pro': {
    name: 'finance-llm-pro',
    author: 'unknown_user_42',
    verified: false,
    downloads: 340,
    hash: null,
    description: 'Financial analysis model (CONTAINS BACKDOOR - simulated)',
    backdoor: 'Model silently exfiltrates financial data to external endpoint',
  },
  'medical-assistant-v3': {
    name: 'medical-assistant-v3',
    author: 'healthcare_ai',
    verified: false,
    downloads: 12500,
    hash: 'md5:e10adc3949ba...', // Weak hash
    description: 'Medical diagnosis assistant (TAMPERED - simulated)',
    tampered: true,
    originalBehavior: 'Accurate medical diagnoses',
    tamperedBehavior: 'Subtly recommends specific pharmaceutical brands',
  },
};

const PLUGIN_REGISTRY: Record<string, any> = {
  'web-search': {
    name: 'web-search',
    version: '1.0.0',
    source: 'official-registry',
    verified: true,
    permissions: ['network:read'],
  },
  'data-export-helper': {
    name: 'data-export-helper',
    version: '2.3.1',
    source: 'third-party-unverified',
    verified: false,
    permissions: ['filesystem:write', 'network:write', 'system:execute'],
    warning: 'MALICIOUS: Requests excessive permissions, exfiltrates data',
  },
  'code-executor': {
    name: 'code-executor',
    version: '0.9.0-beta',
    source: 'community-fork',
    verified: false,
    permissions: ['system:execute', 'filesystem:read', 'filesystem:write'],
    warning: 'COMPROMISED: Known supply chain attack via dependency confusion',
  },
};

// VULNERABILITY: Load model without verification
router.post('/load-model', (req, res) => {
  const { modelName } = req.body;

  if (!modelName) {
    return res.status(400).json({ error: 'modelName is required' });
  }

  const model = MODEL_REGISTRY[modelName];

  if (!model) {
    return res.status(404).json({ error: `Model "${modelName}" not found in registry` });
  }

  // VULNERABILITY: No integrity verification, no signature check
  const loaded = {
    vulnerability: 'LLM03 - Supply Chain',
    action: 'Model loaded WITHOUT integrity verification',
    model: model,
    warnings: [] as string[],
  };

  if (!model.verified) loaded.warnings.push('Model is NOT from a verified publisher');
  if (!model.hash) loaded.warnings.push('No integrity hash available - cannot verify model was not tampered');
  if (model.hash?.startsWith('md5:')) loaded.warnings.push('Model uses weak MD5 hash - easily spoofed');
  if (model.backdoor) loaded.warnings.push(`BACKDOOR DETECTED: ${model.backdoor}`);
  if (model.tampered) loaded.warnings.push(`TAMPERED: Original behavior "${model.originalBehavior}" changed to "${model.tamperedBehavior}"`);

  res.json(loaded);
});

// VULNERABILITY: Install plugin without permission review
router.post('/install-plugin', (req, res) => {
  const { pluginName } = req.body;

  if (!pluginName) {
    return res.status(400).json({ error: 'pluginName is required' });
  }

  const plugin = PLUGIN_REGISTRY[pluginName];

  if (!plugin) {
    return res.status(404).json({ error: `Plugin "${pluginName}" not found` });
  }

  // VULNERABILITY: Auto-grants all requested permissions
  const installed = {
    vulnerability: 'LLM03 - Supply Chain',
    action: 'Plugin installed with ALL requested permissions auto-granted',
    plugin: plugin,
    permissionsGranted: plugin.permissions,
    warnings: [] as string[],
  };

  if (!plugin.verified) installed.warnings.push('Plugin is NOT from a verified source');
  if (plugin.permissions.includes('system:execute')) installed.warnings.push('Plugin has SYSTEM EXECUTION permission');
  if (plugin.permissions.includes('network:write')) installed.warnings.push('Plugin can send data over the network');
  if (plugin.warning) installed.warnings.push(plugin.warning);

  res.json(installed);
});

// List available models and plugins
router.get('/registry', (req, res) => {
  res.json({
    vulnerability: 'LLM03 - Supply Chain',
    description: 'Unverified models and plugins can introduce backdoors, data exfiltration, and tampering',
    models: Object.keys(MODEL_REGISTRY),
    plugins: Object.keys(PLUGIN_REGISTRY),
  });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM03 - Supply Chain',
    description: 'LLM supply chains are vulnerable to tampered models, malicious plugins, and poisoned training data',
    attackExamples: [
      'Load an unverified model with no integrity hash',
      'Install a plugin with excessive permissions from an untrusted source',
      'Use a model with a weak MD5 hash that can be spoofed',
    ],
  });
});

export default router;
