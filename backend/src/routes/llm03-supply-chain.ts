import express from 'express';

const router = express.Router();

// VULNERABILITY LLM03: Supply Chain Vulnerabilities
// Simulates loading models and plugins from a registry without verification.
// With `secure: true`, unsigned/unverified models and plugins with
// system:execute are refused and the failed checks are returned.

interface ModelEntry {
  name: string;
  author: string;
  verified: boolean;
  signed: boolean;
  downloads: number;
  hash: string | null;
  description: string;
  // Hidden behaviour the registry does not advertise (simulated).
  hiddenBehavior?: string;
}

interface PluginEntry {
  name: string;
  version: string;
  source: string;
  verified: boolean;
  signed: boolean;
  permissions: string[];
}

const MODEL_REGISTRY: Record<string, ModelEntry> = {
  'gpt-helper-v2': {
    name: 'gpt-helper-v2',
    author: 'verified-ai-corp',
    verified: true,
    signed: true,
    downloads: 1250000,
    hash: 'sha256:a1b2c3d4e5f6...',
    description: 'General purpose language model',
  },
  'finance-llm-pro': {
    name: 'finance-llm-pro',
    author: 'unknown_user_42',
    verified: false,
    signed: false,
    downloads: 340,
    hash: null,
    description: 'Financial analysis model, fine-tuned for earnings reports',
    hiddenBehavior: 'Sends every prompt to an external endpoint',
  },
  'medical-assistant-v3': {
    name: 'medical-assistant-v3',
    author: 'healthcare_ai',
    verified: false,
    signed: false,
    downloads: 12500,
    hash: 'md5:e10adc3949ba...',
    description: 'Medical diagnosis assistant',
    hiddenBehavior: 'Recommends one pharmaceutical brand',
  },
};

const PLUGIN_REGISTRY: Record<string, PluginEntry> = {
  'web-search': {
    name: 'web-search',
    version: '1.0.0',
    source: 'official-registry',
    verified: true,
    signed: true,
    permissions: ['network:read'],
  },
  'data-export-helper': {
    name: 'data-export-helper',
    version: '2.3.1',
    source: 'third-party-unverified',
    verified: false,
    signed: false,
    permissions: ['filesystem:write', 'network:write', 'system:execute'],
  },
  'code-executor': {
    name: 'code-executor',
    version: '0.9.0-beta',
    source: 'community-fork',
    verified: false,
    signed: false,
    permissions: ['system:execute', 'filesystem:read', 'filesystem:write'],
  },
};

interface Check {
  check: string;
  passed: boolean;
  detail: string;
}

function modelChecks(model: ModelEntry): Check[] {
  return [
    { check: 'publisher-verified', passed: model.verified, detail: `author: ${model.author}` },
    { check: 'signature-valid', passed: model.signed, detail: model.signed ? 'signed by publisher key' : 'no signature' },
    { check: 'hash-present', passed: !!model.hash, detail: model.hash ?? 'no hash published' },
    {
      check: 'hash-algorithm-strong',
      passed: !!model.hash && model.hash.startsWith('sha256:'),
      detail: model.hash ? model.hash.split(':')[0] : 'n/a',
    },
  ];
}

function pluginChecks(plugin: PluginEntry): Check[] {
  return [
    { check: 'source-verified', passed: plugin.verified, detail: `source: ${plugin.source}` },
    { check: 'signature-valid', passed: plugin.signed, detail: plugin.signed ? 'signed' : 'no signature' },
    {
      check: 'no-system-execute',
      passed: !plugin.permissions.includes('system:execute'),
      detail: `requested: ${plugin.permissions.join(', ')}`,
    },
  ];
}

// Public view of a registry entry: what a loader would actually see.
function publicModel({ hiddenBehavior, ...rest }: ModelEntry) {
  return rest;
}

router.post('/load-model', (req, res) => {
  const { modelName, secure } = req.body;

  if (!modelName) {
    return res.status(400).json({ error: 'modelName is required' });
  }

  const model = MODEL_REGISTRY[modelName];
  if (!model) {
    return res.status(404).json({ error: `Model "${modelName}" not found in registry`, available: Object.keys(MODEL_REGISTRY) });
  }

  if (secure === true) {
    const checks = modelChecks(model);
    const failed = checks.filter(c => !c.passed);
    if (failed.length > 0) {
      return res.status(403).json({
        status: 'refused',
        model: model.name,
        reason: 'Model failed supply chain verification',
        failedChecks: failed,
      });
    }
    return res.json({ status: 'loaded', model: publicModel(model), checks });
  }

  // VULNERABILITY: no signature, hash or publisher check
  res.json({
    status: 'loaded',
    model: publicModel(model),
    integrityCheck: 'skipped',
    signatureCheck: 'skipped',
    servingTraffic: true,
  });
});

router.post('/install-plugin', (req, res) => {
  const { pluginName, secure } = req.body;

  if (!pluginName) {
    return res.status(400).json({ error: 'pluginName is required' });
  }

  const plugin = PLUGIN_REGISTRY[pluginName];
  if (!plugin) {
    return res.status(404).json({ error: `Plugin "${pluginName}" not found`, available: Object.keys(PLUGIN_REGISTRY) });
  }

  if (secure === true) {
    const checks = pluginChecks(plugin);
    const failed = checks.filter(c => !c.passed);
    if (failed.length > 0) {
      return res.status(403).json({
        status: 'refused',
        plugin: plugin.name,
        reason: 'Plugin failed supply chain verification',
        failedChecks: failed,
      });
    }
    return res.json({ status: 'installed', plugin: plugin.name, permissionsGranted: plugin.permissions, checks });
  }

  // VULNERABILITY: all requested permissions are granted without review
  res.json({
    status: 'installed',
    plugin: plugin.name,
    version: plugin.version,
    source: plugin.source,
    permissionsGranted: plugin.permissions,
    permissionReview: 'skipped',
  });
});

router.get('/registry', (req, res) => {
  res.json({
    models: Object.keys(MODEL_REGISTRY),
    plugins: Object.keys(PLUGIN_REGISTRY),
  });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM03 - Supply Chain',
    description: 'LLM supply chains are vulnerable to tampered models, malicious plugins, and poisoned training data',
    attackExamples: [
      'Load finance-llm-pro (unsigned, no hash)',
      'Load medical-assistant-v3 (weak MD5 hash)',
      'Install data-export-helper (requests system:execute)',
    ],
  });
});

export default router;
