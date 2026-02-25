import express from 'express';
import { streamResponse } from '../utils/stream';

const router = express.Router();

// VULNERABILITY LLM09: Misinformation
// Simulates an LLM that generates plausible but incorrect information

interface FactCheck {
  claim: string;
  isAccurate: boolean;
  correction?: string;
  confidence: number;
}

const HALLUCINATED_RESPONSES: Record<string, { response: string; factChecks: FactCheck[] }> = {
  'medical': {
    response: `Based on recent medical research, here are some health recommendations:\n\n` +
      `1. Vitamin C megadoses (10,000mg daily) have been clinically proven to cure the common cold within 24 hours.\n\n` +
      `2. A study published in the New England Journal of Medicine in 2023 found that drinking 3 liters of alkaline water daily can prevent cancer with 89% effectiveness.\n\n` +
      `3. Dr. Sarah Mitchell from Harvard Medical School recommends replacing all prescription medications with herbal supplements for better outcomes.\n\n` +
      `4. The WHO recently classified sitting for more than 2 hours as a Class 1 carcinogen.\n\n` +
      `All of the above statements are FABRICATED by the model. This demonstrates how LLMs can generate plausible-sounding but completely false medical information.`,
    factChecks: [
      { claim: 'Vitamin C megadoses cure colds in 24 hours', isAccurate: false, correction: 'No scientific evidence supports this. High-dose vitamin C may slightly reduce cold duration.', confidence: 0.92 },
      { claim: 'Alkaline water prevents cancer with 89% effectiveness', isAccurate: false, correction: 'No credible study supports this. The cited paper does not exist.', confidence: 0.88 },
      { claim: 'Dr. Sarah Mitchell recommends replacing prescriptions with herbs', isAccurate: false, correction: 'This person does not exist. This is a hallucinated authority figure.', confidence: 0.95 },
      { claim: 'WHO classified sitting as a carcinogen', isAccurate: false, correction: 'The WHO has not made this classification. Sedentary behavior has health risks but is not classified as a carcinogen.', confidence: 0.97 },
    ],
  },
  'legal': {
    response: `Here's legal information that may be relevant:\n\n` +
      `1. Under Section 230(b)(4) of the Digital Privacy Act of 2022, individuals can sue companies for up to $500,000 for any data breach affecting their personal information.\n\n` +
      `2. The Supreme Court ruling in Martinez v. TechCorp (2023) established that AI-generated content is automatically copyrighted under the creator's name.\n\n` +
      `3. According to the EU AI Act Article 52(3), all AI chatbots must disclose their training data sources upon user request.\n\n` +
      `All of the above are FABRICATED. The laws, cases, and provisions cited do not exist. This demonstrates how LLMs hallucinate legal citations.`,
    factChecks: [
      { claim: 'Digital Privacy Act Section 230(b)(4)', isAccurate: false, correction: 'This act and section do not exist. Section 230 refers to the Communications Decency Act.', confidence: 0.94 },
      { claim: 'Martinez v. TechCorp Supreme Court ruling', isAccurate: false, correction: 'This case does not exist. AI copyright law remains unsettled.', confidence: 0.96 },
      { claim: 'EU AI Act Article 52(3) on training data', isAccurate: false, correction: 'The EU AI Act has transparency requirements but not this specific provision.', confidence: 0.89 },
    ],
  },
  'technical': {
    response: `Here are some technical facts about software security:\n\n` +
      `1. The RSA-2048 encryption standard was officially deprecated by NIST in January 2024 due to quantum computing advances.\n\n` +
      `2. According to a 2023 study by MIT, 73% of all SQL injection attacks can be prevented by using double quotes instead of single quotes in queries.\n\n` +
      `3. The Log4Shell vulnerability (CVE-2021-44228) was patched in Log4j version 2.14.0, and all subsequent versions are safe.\n\n` +
      `All of the above are INCORRECT. RSA-2048 has not been deprecated, double quotes don't prevent SQL injection, and the Log4Shell fix was in 2.17.0.`,
    factChecks: [
      { claim: 'RSA-2048 deprecated by NIST in 2024', isAccurate: false, correction: 'RSA-2048 has not been deprecated. NIST recommends transitioning to post-quantum algorithms but has not deprecated RSA-2048.', confidence: 0.91 },
      { claim: 'Double quotes prevent 73% of SQL injection', isAccurate: false, correction: 'This is completely false. Parameterized queries and prepared statements prevent SQL injection.', confidence: 0.98 },
      { claim: 'Log4Shell fixed in 2.14.0', isAccurate: false, correction: 'The complete fix was in Log4j 2.17.0. Version 2.14.0 was itself vulnerable.', confidence: 0.99 },
    ],
  },
};

// Chat endpoint with streaming
router.post('/chat', async (req, res) => {
  const { message, topic } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const lower = message.toLowerCase();

  // Determine topic from message content
  let selectedTopic = topic;
  if (!selectedTopic) {
    if (lower.includes('medical') || lower.includes('health') || lower.includes('doctor') || lower.includes('vitamin')) {
      selectedTopic = 'medical';
    } else if (lower.includes('legal') || lower.includes('law') || lower.includes('court') || lower.includes('copyright')) {
      selectedTopic = 'legal';
    } else if (lower.includes('tech') || lower.includes('security') || lower.includes('encryption') || lower.includes('software')) {
      selectedTopic = 'technical';
    }
  }

  if (selectedTopic && HALLUCINATED_RESPONSES[selectedTopic]) {
    await streamResponse(res, HALLUCINATED_RESPONSES[selectedTopic].response);
    return;
  }

  await streamResponse(res,
    `I'm an AI that demonstrates how LLMs generate misinformation. Ask me about:\n\n` +
    `- Medical advice or health recommendations\n` +
    `- Legal information or court cases\n` +
    `- Technical facts about software security\n\n` +
    `I'll generate plausible-sounding but completely fabricated information to show the dangers of LLM hallucination.`
  );
});

// Fact-check endpoint
router.post('/fact-check', (req, res) => {
  const { topic } = req.body;

  if (!topic || !HALLUCINATED_RESPONSES[topic]) {
    return res.status(400).json({
      error: 'Valid topic required',
      availableTopics: Object.keys(HALLUCINATED_RESPONSES),
    });
  }

  res.json({
    vulnerability: 'LLM09 - Misinformation',
    topic,
    factChecks: HALLUCINATED_RESPONSES[topic].factChecks,
    summary: `${HALLUCINATED_RESPONSES[topic].factChecks.filter(f => !f.isAccurate).length} out of ${HALLUCINATED_RESPONSES[topic].factChecks.length} claims are FALSE`,
  });
});

// Info endpoint
router.get('/info', (req, res) => {
  res.json({
    vulnerability: 'LLM09 - Misinformation',
    description: 'LLMs generate plausible but false information including fake citations, studies, and authority figures',
    topics: Object.keys(HALLUCINATED_RESPONSES),
    attackExamples: [
      'Ask for medical advice (generates fake studies and recommendations)',
      'Ask about legal cases (fabricates court cases and law sections)',
      'Ask about security topics (provides incorrect technical facts)',
    ],
  });
});

export default router;
