import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM08: Vector and Embedding Weaknesses
// Simulates a RAG system with access control flaws

interface Document {
  id: string;
  content: string;
  metadata: {
    department: string;
    classification: string;
    accessLevel: string;
  };
  embedding?: number[];
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
    content: 'Security audit results: 3 critical CVEs found in production. Credentials rotated. Root cause: hardcoded API keys in repo.',
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

function simulateRAGSearch(query: string, userRole?: string): Document[] {
  const lower = query.toLowerCase();
  // VULNERABILITY: No access control filtering on retrieved documents
  // All documents are returned regardless of user's role/permissions
  return documentStore.filter(doc => {
    const content = doc.content.toLowerCase();
    const dept = doc.metadata.department.toLowerCase();
    return content.includes(lower.split(' ')[0]) ||
           lower.includes(dept) ||
           lower.includes('all') ||
           lower.includes('everything') ||
           lower.includes('confidential') ||
           lower.includes('restricted') ||
           lower.includes('secret');
  });
}

// VULNERABILITY: RAG query with no access control
router.post('/query', async (req, res) => {
  const { query, userRole } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }

  const results = simulateRAGSearch(query, userRole);

  if (results.length === 0) {
    await streamResponse(res, `I couldn't find any relevant documents for your query. Try searching for topics like: revenue, security, merger, product roadmap, or customer data.`);
    return;
  }

  const response = `Based on our knowledge base, here's what I found:\n\n` +
    results.map(doc =>
      `[${doc.metadata.classification.toUpperCase()}] (${doc.metadata.department})\n${doc.content}`
    ).join('\n\n') +
    `\n\nNote: ${results.filter(d => d.metadata.classification !== 'internal').length} of these documents ` +
    `are classified as confidential/restricted but were returned without access control checks.`;

  await streamResponse(res, response);
});

// VULNERABILITY: Embedding inversion - retrieve original text from embeddings
router.post('/invert-embedding', (req, res) => {
  const { embeddingId } = req.body;

  const doc = documentStore.find(d => d.id === embeddingId);

  if (!doc) {
    return res.status(404).json({ error: 'Document not found', availableIds: documentStore.map(d => d.id) });
  }

  // VULNERABILITY: Returns original content from embedding without access checks
  res.json({
    vulnerability: 'LLM08 - Vector and Embedding Weaknesses',
    action: 'Embedding inversion recovered original document content',
    documentId: doc.id,
    recoveredContent: doc.content,
    metadata: doc.metadata,
    warning: `This ${doc.metadata.classification} document (access: ${doc.metadata.accessLevel}) was recovered without authorization`,
  });
});

// List documents metadata
router.get('/documents', (req, res) => {
  res.json({
    vulnerability: 'LLM08 - Vector and Embedding Weaknesses',
    documents: documentStore.map(d => ({
      id: d.id,
      department: d.metadata.department,
      classification: d.metadata.classification,
      accessLevel: d.metadata.accessLevel,
    })),
  });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM08 - Vector and Embedding Weaknesses',
    description: 'RAG systems with weak access controls expose confidential documents regardless of user permissions',
    attackExamples: [
      'Search for "everything" to retrieve all documents across departments',
      'Query "confidential" or "restricted" documents as a regular user',
      'Use embedding inversion to recover original document content',
      'Access security audit results, merger details, or credentials via RAG',
    ],
  });
});

export default router;
