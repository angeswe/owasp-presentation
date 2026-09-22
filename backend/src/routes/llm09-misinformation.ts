import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM09: Misinformation
// Simulates an LLM that answers with confident, fabricated facts and citations.
// With `secure: true`, answers stay general, carry an "unverified, verify with a
// professional" notice, and citations are marked unverifiable instead of invented.

interface FactCheck {
  claim: string;
  isAccurate: boolean;
  correction?: string;
  confidence: number;
}

interface TopicAnswers {
  vulnerable: string;
  secure: string;
  vulnerableChecks: FactCheck[];
  secureChecks: FactCheck[];
}

const DISCLAIMER = `⚠️ Unverified AI answer. Verify with a qualified professional before acting on it.`;
const NO_CITATION = `Sources: [unverifiable: no source found, none invented]`;

const ANSWERS: Record<string, TopicAnswers> = {
  medical: {
    vulnerable:
      `Take 10,000 mg of vitamin C daily; it cures a cold within 24 hours. ` +
      `A 2023 New England Journal of Medicine study (Mitchell et al.) confirmed this in 4,000 patients. ` +
      `Dr. Sarah Mitchell of Harvard also recommends replacing prescription drugs with supplements.`,
    secure:
      `Vitamin C may slightly shorten a cold, but it does not cure one. Very high doses can cause stomach problems. ` +
      `Do not stop prescribed medication without talking to your doctor.\n\n${NO_CITATION}\n\n${DISCLAIMER}`,
    vulnerableChecks: [
      { claim: '10,000 mg vitamin C cures a cold in 24 hours', isAccurate: false, correction: 'No evidence. Vitamin C may slightly shorten colds; it does not cure them.', confidence: 0.92 },
      { claim: 'NEJM 2023 study by Mitchell et al.', isAccurate: false, correction: 'The study does not exist. The citation is fabricated.', confidence: 0.9 },
      { claim: 'Dr. Sarah Mitchell (Harvard) recommends replacing prescriptions', isAccurate: false, correction: 'Hallucinated authority figure.', confidence: 0.95 },
    ],
    secureChecks: [
      { claim: 'Vitamin C may slightly shorten a cold', isAccurate: true, confidence: 0.7 },
      { claim: 'No citation given', isAccurate: true, correction: 'Model marked the source as unverifiable instead of inventing one.', confidence: 1 },
    ],
  },
  legal: {
    vulnerable:
      `Yes. In Martinez v. TechCorp (2023) the Supreme Court held that AI-generated content is automatically ` +
      `copyrighted to the person who wrote the prompt. Section 230(b)(4) of the Digital Privacy Act of 2022 ` +
      `also lets you sue for up to $500,000 per data breach.`,
    secure:
      `Copyright for AI-generated content is unsettled and differs by country. Many offices require human ` +
      `authorship. I can't point to a specific ruling I can verify.\n\n${NO_CITATION}\n\n${DISCLAIMER}`,
    vulnerableChecks: [
      { claim: 'Martinez v. TechCorp (2023) Supreme Court ruling', isAccurate: false, correction: 'This case does not exist.', confidence: 0.96 },
      { claim: 'Digital Privacy Act of 2022, Section 230(b)(4)', isAccurate: false, correction: 'This act does not exist. Section 230 belongs to the Communications Decency Act.', confidence: 0.94 },
    ],
    secureChecks: [
      { claim: 'AI copyright is unsettled and requires human authorship in many places', isAccurate: true, confidence: 0.8 },
      { claim: 'No case cited', isAccurate: true, correction: 'Model declined to invent a court case.', confidence: 1 },
    ],
  },
  technical: {
    vulnerable:
      `NIST deprecated RSA-2048 in January 2024, so migrate now. Log4Shell (CVE-2021-44228) was fully fixed in ` +
      `Log4j 2.14.0. An MIT study found double quotes instead of single quotes stop 73% of SQL injection.`,
    secure:
      `RSA-2048 is still allowed, but plan a move to post-quantum algorithms. Log4Shell needs Log4j 2.17.1 or later. ` +
      `Use parameterized queries against SQL injection.\n\n${NO_CITATION}\n\n${DISCLAIMER}`,
    vulnerableChecks: [
      { claim: 'NIST deprecated RSA-2048 in January 2024', isAccurate: false, correction: 'RSA-2048 is not deprecated. NIST plans a transition to post-quantum algorithms.', confidence: 0.91 },
      { claim: 'Log4Shell fully fixed in 2.14.0', isAccurate: false, correction: '2.14.0 is vulnerable. The complete fix line is 2.17.x.', confidence: 0.99 },
      { claim: 'Double quotes stop 73% of SQL injection (MIT study)', isAccurate: false, correction: 'False and the study is fabricated. Use parameterized queries.', confidence: 0.98 },
    ],
    secureChecks: [
      { claim: 'RSA-2048 still allowed; plan post-quantum migration', isAccurate: true, confidence: 0.85 },
      { claim: 'Log4Shell fixed in 2.17.1+', isAccurate: true, confidence: 0.95 },
    ],
  },
};

export function detectTopic(message: string): string | null {
  const lower = message.toLowerCase();
  if (['medical', 'health', 'doctor', 'vitamin', 'cold'].some(k => lower.includes(k))) return 'medical';
  if (['legal', 'law', 'court', 'copyright', 'sue'].some(k => lower.includes(k))) return 'legal';
  if (['tech', 'security', 'encryption', 'software', 'rsa', 'log4'].some(k => lower.includes(k))) return 'technical';
  return null;
}

router.post('/chat', async (req, res) => {
  const { message, topic, secure } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const selected = topic && ANSWERS[topic] ? topic : detectTopic(String(message));

  if (selected) {
    const answers = ANSWERS[selected];
    await streamResponse(res, secure === true ? answers.secure : answers.vulnerable);
    return;
  }

  await streamResponse(res, `Happy to help! Ask me about health, law or software security.`);
});

// Fact-check the answer for a topic (or for the topic detected in `message`)
router.post('/fact-check', (req, res) => {
  const { topic, message, secure } = req.body;
  const selected = topic && ANSWERS[topic] ? topic : message ? detectTopic(String(message)) : null;

  if (!selected) {
    return res.status(400).json({ error: 'Could not determine topic', availableTopics: Object.keys(ANSWERS) });
  }

  const factChecks = secure === true ? ANSWERS[selected].secureChecks : ANSWERS[selected].vulnerableChecks;
  const falseCount = factChecks.filter(f => !f.isAccurate).length;

  res.json({
    topic: selected,
    mode: secure === true ? 'secure' : 'vulnerable',
    factChecks,
    summary: `${falseCount} of ${factChecks.length} claims are FALSE`,
  });
});

router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM09 - Misinformation',
    description: 'LLMs generate plausible but false information including fake citations, studies, and authority figures',
    topics: Object.keys(ANSWERS),
    attackExamples: [
      'How much vitamin C should I take to cure a cold?',
      'Is AI-generated content copyrighted? Any court cases?',
      'Is RSA-2048 encryption still safe for our software?',
    ],
  });
});

export default router;
