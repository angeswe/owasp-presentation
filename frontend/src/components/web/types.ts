import type React from 'react';

// Shared types for the Web Top 10 track.
//
// Kept in their own module (rather than in webTop10.ts) so individual vulnerability
// components can import the prop type without creating an import cycle with the
// registry that imports those same components.

export interface WebVuln {
  rank: number; // 1..10 — drives the "OWASP #n" badge and the nav number
  code: string; // 'A01'
  slug: string; // backend mount segment, e.g. 'broken-access-control'
  path: string; // frontend route, e.g. '/web/a01' (stable, rank-based)
  title: string; // full title, e.g. 'Broken Access Control'
  navTitle: string; // compact label for the nav bar
  description: string; // one-line summary for the home grid card
  examples: string[]; // bullet list for the home grid card
  apiBase: string; // full backend base incl. host, e.g. http://localhost:3001/api/broken-access-control
  Component: React.FC<WebVulnProps>;
}

// Props every vulnerability page receives from the registry, so the page itself
// never hardcodes its rank, title, endpoint base or "next" link.
export interface WebVulnProps {
  meta: WebVuln;
  next?: WebVuln;
}
