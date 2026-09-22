import type React from 'react';

// Shared types for the OWASP Top 10 for LLM Applications track.
//
// Kept in their own module (rather than in llmTop10.ts) so individual pages can
// import the prop type without an import cycle with the registry, which imports
// those same pages. Mirrors web/types.ts.

export interface LLMVuln {
  rank: number; // 1..10, drives the "OWASP LLM #n" badge and the nav number
  code: string; // 'LLM01'
  slug: string; // backend mount segment, e.g. 'llm01'
  path: string; // frontend route, e.g. '/llm/l01'
  title: string; // full title, e.g. 'Prompt Injection'
  navTitle: string; // compact label for the nav bar
  description: string; // one-line summary for the home grid card
  examples: string[]; // bullet list for the home grid card
  apiBase: string; // full backend base incl. host, e.g. http://localhost:3001/api/llm01
  Component: React.FC<LLMVulnProps>;
}

// Props every LLM page receives from the registry, so the page never hardcodes
// its rank, title, endpoint base or "next" link.
export interface LLMVulnProps {
  meta: LLMVuln;
  next?: LLMVuln;
}
