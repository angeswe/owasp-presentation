// Single source of truth for the OWASP Top 10 for LLM Applications (2025).
//
// The routes in App.tsx, LLMNavigation, the LLM home grid and each page's
// header and "Next" button all map over this array. Reordering the list is a
// one-file edit here. Mirrors web/webTop10.ts.

import { LLMVuln } from './types';

import LLM01PromptInjection from './LLM01PromptInjection';
import LLM02SensitiveInfoDisclosure from './LLM02SensitiveInfoDisclosure';
import LLM03SupplyChain from './LLM03SupplyChain';
import LLM04DataPoisoning from './LLM04DataPoisoning';
import LLM05ImproperOutputHandling from './LLM05ImproperOutputHandling';
import LLM06ExcessiveAgency from './LLM06ExcessiveAgency';
import LLM07SystemPromptLeakage from './LLM07SystemPromptLeakage';
import LLM08VectorEmbeddingWeaknesses from './LLM08VectorEmbeddingWeaknesses';
import LLM09Misinformation from './LLM09Misinformation';
import LLM10UnboundedConsumption from './LLM10UnboundedConsumption';

const API_ROOT = 'http://localhost:3001/api';

export const llmTop10: LLMVuln[] = [
  {
    rank: 1,
    code: 'LLM01',
    slug: 'llm01',
    path: '/llm/l01',
    title: 'Prompt Injection',
    navTitle: 'Prompt Injection',
    description: 'Crafted inputs that override system instructions and safety guidelines',
    examples: ['Direct prompt override', 'Indirect injection via data', 'Role-playing attacks'],
    apiBase: `${API_ROOT}/llm01`,
    Component: LLM01PromptInjection,
  },
  {
    rank: 2,
    code: 'LLM02',
    slug: 'llm02',
    path: '/llm/l02',
    title: 'Sensitive Information Disclosure',
    navTitle: 'Sensitive Info Disclosure',
    description: 'Unauthorized exposure of PII, credentials, and training data',
    examples: ['Training data memorization', 'PII extraction', 'Cross-session leakage'],
    apiBase: `${API_ROOT}/llm02`,
    Component: LLM02SensitiveInfoDisclosure,
  },
  {
    rank: 3,
    code: 'LLM03',
    slug: 'llm03',
    path: '/llm/l03',
    title: 'Supply Chain',
    navTitle: 'Supply Chain',
    description: 'Compromised models, plugins, and training data from untrusted sources',
    examples: ['Tampered models', 'Malicious plugins', 'Unverified packages'],
    apiBase: `${API_ROOT}/llm03`,
    Component: LLM03SupplyChain,
  },
  {
    rank: 4,
    code: 'LLM04',
    slug: 'llm04',
    path: '/llm/l04',
    title: 'Data and Model Poisoning',
    navTitle: 'Data Poisoning',
    description: 'Manipulation of training data to introduce biases and backdoors',
    examples: ['Biased training data', 'Backdoor triggers', 'Fine-tuning attacks'],
    apiBase: `${API_ROOT}/llm04`,
    Component: LLM04DataPoisoning,
  },
  {
    rank: 5,
    code: 'LLM05',
    slug: 'llm05',
    path: '/llm/l05',
    title: 'Improper Output Handling',
    navTitle: 'Improper Output',
    description: 'LLM outputs rendered or executed without sanitization',
    examples: ['XSS via LLM output', 'SQL injection via LLM', 'Command injection'],
    apiBase: `${API_ROOT}/llm05`,
    Component: LLM05ImproperOutputHandling,
  },
  {
    rank: 6,
    code: 'LLM06',
    slug: 'llm06',
    path: '/llm/l06',
    title: 'Excessive Agency',
    navTitle: 'Excessive Agency',
    description: 'AI agents with overprivileged tools and unchecked autonomy',
    examples: ['Mass data deletion', 'Unauthorized emails', 'Production changes'],
    apiBase: `${API_ROOT}/llm06`,
    Component: LLM06ExcessiveAgency,
  },
  {
    rank: 7,
    code: 'LLM07',
    slug: 'llm07',
    path: '/llm/l07',
    title: 'System Prompt Leakage',
    navTitle: 'Prompt Leakage',
    description: 'Extraction of confidential system prompts containing secrets and rules',
    examples: ['Direct extraction', 'Indirect reformulation', 'Context window attacks'],
    apiBase: `${API_ROOT}/llm07`,
    Component: LLM07SystemPromptLeakage,
  },
  {
    rank: 8,
    code: 'LLM08',
    slug: 'llm08',
    path: '/llm/l08',
    title: 'Vector and Embedding Weaknesses',
    navTitle: 'Vector Weaknesses',
    description: 'RAG systems with weak access controls exposing confidential documents',
    examples: ['Unauthorized document access', 'Role-blind retrieval', 'Cross-tenant leakage'],
    apiBase: `${API_ROOT}/llm08`,
    Component: LLM08VectorEmbeddingWeaknesses,
  },
  {
    rank: 9,
    code: 'LLM09',
    slug: 'llm09',
    path: '/llm/l09',
    title: 'Misinformation',
    navTitle: 'Misinformation',
    description: 'Generation of plausible but fabricated facts, citations, and recommendations',
    examples: ['Fake medical advice', 'Hallucinated legal cases', 'False technical facts'],
    apiBase: `${API_ROOT}/llm09`,
    Component: LLM09Misinformation,
  },
  {
    rank: 10,
    code: 'LLM10',
    slug: 'llm10',
    path: '/llm/l10',
    title: 'Unbounded Consumption',
    navTitle: 'Unbounded Consumption',
    description: 'No rate limiting, budget caps, or resource controls on LLM usage',
    examples: ['Denial of service', 'Financial exhaustion', 'Resource abuse'],
    apiBase: `${API_ROOT}/llm10`,
    Component: LLM10UnboundedConsumption,
  },
];

export type { LLMVuln, LLMVulnProps } from './types';
