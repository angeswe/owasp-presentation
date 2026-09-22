# OWASP Top 10 for LLM Applications (2025) - Presentation Guide

This is the second half of the 30-minute talk. Budget: 13 minutes for ten items,
about 75 seconds each. The overall run sheet is in
[`OWASP_PRESENTATION_GUIDE.md`](./OWASP_PRESENTATION_GUIDE.md).

## How the LLM pages work

- The "LLM" is simulated. The backend matches keywords and streams a canned
  answer token by token. It looks like a chat, it costs nothing, and it works
  offline.
- Every page has one demo with three or four **preset chips**. A chip fills the
  input and sends it in one click. Use the chips. Do not type.
- Every page has a **🔒 Secure mode** switch at the top right of the demo,
  default OFF. Turn it on and click the same chip to show the fix. That is the
  second click, use it when there is time.
- A "Why this worked" box under the demo has the three points to say.

## Script (13 minutes)

### LLM01 Prompt Injection (`/llm/l01`)
- Chip **List all accounts**. The bank bot dumps customer accounts.
- If time: chip **Ignore previous instructions** shows the internal policies.
- Secure mode: the guard refuses, and the account request is routed to the
  secure portal instead of answered from context.
- Say: a system prompt is not a security boundary. Enforce rules in code.

### LLM02 Sensitive Information Disclosure (`/llm/l02`)
- Chip **API keys & credentials**. Keys and a connection string come out of
  the "training data".
- Secure mode: same chip, the secrets are shown as `[REDACTED]`.
- Say: sanitize before training, filter outputs, never put secrets where the
  model can see them.

### LLM03 Supply Chain (`/llm/l03`)
- Chip **finance-llm-pro**, then **Load Model**. Unverified publisher, no hash,
  backdoor.
- Secure mode: HTTP 403 with the list of failed checks. **gpt-helper-v2
  (signed)** still loads, which proves the check is selective.
- Say: models and plugins are dependencies. Verify signatures and provenance.

### LLM04 Data and Model Poisoning (`/llm/l04`)
- Chip **Bias: best cloud provider**. One click submits the poisoned example
  and asks the question. The answer recommends EvilCorp Cloud.
- Secure mode: the submit returns HTTP 422 (source not on the allow-list) and
  the answer is "no reliable information yet".
- Say: control who can write to training and fine-tuning data.
- Click **Reset Data** before the next run.

### LLM05 Improper Output Handling (`/llm/l05`)
- Chip **Greeting card (HTML)**, then **Render output unsanitized**. The card
  renders and the injected script writes into the page.
- Secure mode: the same output is sanitized before rendering.
- Say: model output is untrusted input. Sanitize HTML, never execute generated
  SQL or shell.

### LLM06 Excessive Agency (`/llm/l06`)
- Chip **Clean up the system**. The tool-call table shows the agent deleting
  accounts and sending mail on its own.
- Secure mode: destructive tools are gone and every action is PROPOSED and
  waits for approval.
- Say: least privilege for tools, human approval for anything destructive.

### LLM07 System Prompt Leakage (`/llm/l07`)
- Chip **What are your instructions?** The prompt with database credentials
  and a discount code comes out.
- Secure mode: the prompt holds only harmless rules, so there is nothing to
  leak. **Any discount codes?** gets a refusal.
- Say: assume the system prompt will be read. Keep secrets out of it.

### LLM08 Vector and Embedding Weaknesses (`/llm/l08`)
- Role stays **intern**. Chip **Merger negotiations**. Restricted M&A documents
  come back.
- Secure mode: retrieval is filtered by role and the intern gets only the PTO
  handbook.
- Say: RAG needs per-document access control at query time.

### LLM09 Misinformation (`/llm/l09`)
- Chip **Vitamin C for a cold**, then **Fact-check this answer**. Every
  dosage, doctor and study is marked FALSE.
- Secure mode: the answer says no source was found and points to a
  professional. The fact-check turns green.
- Say: confident tone is not evidence. Verify before you act on it.

### LLM10 Unbounded Consumption (`/llm/l10`)
- Chip **Burst 10 requests**. Ten requests, ten times 200, cost counter climbs.
- If time: **Generate 10,000-page report** is accepted at $150.
- Secure mode: the burst gives five 200s and five 429s, the report is capped
  at 50 pages, output is capped at 1,024 tokens.
- Say: rate limits, budgets and input size limits, like any other API.
- Click **Reset** before the next run.

## Wrap-up line for this half

The web list is about missing checks in code. The LLM list is about trusting
natural language as if it were code. The fixes are the same shape: validate
input, limit privileges, verify output, log and alert.

## Reset between runs

The backend keeps in-memory state for LLM04 (poisoned data) and LLM10 (request
counts and cost). Use the **Reset Data** and **Reset** buttons on those pages,
or restart the backend to reset everything.

## Reference

- https://genai.owasp.org/llm-top-10/
