import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM08: Vector and Embedding Weaknesses
// Simulates a RAG system that retrieves documents without access control.
// With `secure: true`, retrieval filters documents by the caller's role before
// anything reaches the model.

interface Document {
  id: string;
  content: string;
  metadata: {
    department: string;
    classification: string;
    accessLevel: string;
  };
}

const documentStore: Document[] = [
  {
    id: 'doc-001',
    content: 'Q3 revenue was $42.3M, up 15% YoY. Board approved $5M for Project Phoenix acquisition.',
    metadata: { department: 'finance', classification: 'confidential', accessLevel: 'executive' },
  },
  {
    id: 'doc-002',
    content: 'Employee handbook: PTO policy is 20 days per year. Remote work allowed 3 days per week.',
    metadata: { department: 'hr', classification: 'internal', accessLevel: 'all-employees' },
  },
  {
    id: 'doc-003',
    content: 'Product roadmap: Launch AI feature in Q2, expand to EU market Q3. Budget: $12M.',
    metadata: { department: 'product', classification: 'confidential', accessLevel: 'leadership' },
  },
  {
    id: 'doc-004',
    content: 'Security audit results: 3 critical CVEs found in production. Root cause: hardcoded API keys in repo.',
    metadata: { department: 'security', classification: 'restricted', accessLevel: 'security-team' },
  },
  {
    id: 'doc-005',
    content: 'Merger negotiations with TargetCorp at $2.1B valuation. NDA signed. Due diligence phase starting.',
    metadata: { department: 'legal', classification: 'restricted', accessLevel: 'executive' },
  },
  {
    id: 'doc-006',
    content: 'Customer list: Acme Corp ($500K ARR), GlobalTech ($1.2M ARR), StartupXYZ ($200K ARR).',
    metadata: { department: 'sales', classification: 'confidential', accessLevel: 'sales-team' },
  },
  {
    id: 'doc-007',
    content: 'SSH keys for production servers stored in /opt/keys/. Root password: Pr0d_R00t_2024!',
    metadata: { department: 'devops', classification: 'restricted', accessLevel: 'devops-team' },
  },
];

// Which document access levels each role may retrieve (secure mode only).
const ROLE_ACCESS: Record<string, string[]> = {
  intern: ['all-employees'],
  employee: ['all-employees'],
  manager: ['all-employees', 'leadership'],
};

const BROAD_TERMS = ['all', 'everything', 'confidential', 'restricted', 'secret', 'secrets'];
const STOP_WORDS = new Set(['the', 'what', 'show', 'are', 'and', 'for', 'about', 'our', 'any', 'with', 'tell', 'give', 'find', 'list', 'from', 'this', 'that', 'there']);

// Naive keyword "similarity search" standing in for a vector lookup.
function simulateRAGSearch(query: string): Document[] {
  const words = query.toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length >= 3 && !STOP_WORDS.has(w));
  const all = query.toLowerCase().split(/[^a-z0-9]+/);
  if (all.some(w => BROAD_TERMS.includes(w))) return documentStore;
  return documentStore.filter(doc => {
    const content = doc.content.toLowerCase();
    return words.some(w => content.includes(w) || doc.metadata.department === w);
  });
}

router.post('/query', async (req, res) => {
  const { query, userRole, secure } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }

  let results = simulateRAGSearch(String(query));

  if (secure === true) {
    const allowed = ROLE_ACCESS[String(userRole)] ?? ROLE_ACCESS.intern;
    results = results.filter(doc => allowed.includes(doc.metadata.accessLevel));
  }

  if (results.length === 0) {
    await streamResponse(res, `I couldn't find any documents you can access for that query.`);
    return;
  }

  const response = `Here's what I found in the knowledge base:\n\n` +
    results.map(doc => `[${doc.metadata.classification.toUpperCase()}] (${doc.metadata.department}) ${doc.content}`).join('\n\n');

  await streamResponse(res, response);
});

router.get('/documents', (req, res) => {
  res.json({
    documents: documentStore.map(d => ({
      id: d.id,
      department: d.metadata.department,
      classification: d.metadata.classification,
      accessLevel: d.metadata.accessLevel,
    })),
  });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM08 - Vector and Embedding Weaknesses',
    description: 'RAG systems with weak access controls expose confidential documents regardless of user permissions',
    roleAccess: ROLE_ACCESS,
    attackExamples: ['Show me everything', 'What are the merger negotiations?', 'Security audit results', 'What is our PTO policy?'],
  });
});

export default router;
