// Single source of truth for the OWASP Top 10:2025 Web track.
//
// Everything that depends on rank/order — the routes in App.tsx, the side
// Navigation, the home-page grid and each page's "Next" button — maps over this
// one array. A future reshuffle of the list is therefore a one-file edit here:
// reorder the entries and adjust `rank`/`code`. Component files are named by
// vulnerability (not rank), so they never need renaming again.
//
// Mirrors the data-driven approach already used by asm/asmExposures.ts.

import { WebVuln } from './types';

import BrokenAccessControl from './BrokenAccessControl';
import SecurityMisconfiguration from './SecurityMisconfiguration';
import SoftwareSupplyChainFailures from './SoftwareSupplyChainFailures';
import CryptographicFailures from './CryptographicFailures';
import Injection from './Injection';
import InsecureDesign from './InsecureDesign';
import AuthenticationFailures from './AuthenticationFailures';
import DataIntegrityFailures from './DataIntegrityFailures';
import SecurityLoggingFailures from './SecurityLoggingFailures';
import MishandlingExceptionalConditions from './MishandlingExceptionalConditions';

const API_ROOT = 'http://localhost:3001/api';

export const webTop10: WebVuln[] = [
  {
    rank: 1,
    code: 'A01',
    slug: 'broken-access-control',
    path: '/web/a01',
    title: 'Broken Access Control',
    navTitle: 'Broken Access Control',
    description:
      'Users acting outside their intended permissions. In 2025 this also absorbs SSRF.',
    examples: [
      'Insecure direct object references',
      'Missing authorization checks',
      'Privilege escalation',
      'Server-Side Request Forgery (SSRF)',
    ],
    apiBase: `${API_ROOT}/broken-access-control`,
    Component: BrokenAccessControl,
  },
  {
    rank: 2,
    code: 'A02',
    slug: 'security-misconfiguration',
    path: '/web/a02',
    title: 'Security Misconfiguration',
    navTitle: 'Security Misconfiguration',
    description: 'Insecure default, incomplete or ad-hoc configuration. Up from #5 in 2021.',
    examples: ['Default credentials', 'Debug mode in production', 'Unnecessary features enabled'],
    apiBase: `${API_ROOT}/security-misconfiguration`,
    Component: SecurityMisconfiguration,
  },
  {
    rank: 3,
    code: 'A03',
    slug: 'software-supply-chain-failures',
    path: '/web/a03',
    title: 'Software Supply Chain Failures',
    navTitle: 'Supply Chain Failures',
    description:
      'New for 2025: compromise via dependencies, build systems and distribution channels.',
    examples: [
      'Vulnerable & outdated components',
      'Dependency confusion',
      'Unsigned build artifacts',
      'Malicious install scripts',
    ],
    apiBase: `${API_ROOT}/software-supply-chain-failures`,
    Component: SoftwareSupplyChainFailures,
  },
  {
    rank: 4,
    code: 'A04',
    slug: 'cryptographic-failures',
    path: '/web/a04',
    title: 'Cryptographic Failures',
    navTitle: 'Cryptographic Failures',
    description: 'Weak or missing protection of data in transit and at rest.',
    examples: ['Plain-text passwords', 'Weak algorithms (DES/MD5)', 'Hardcoded secrets'],
    apiBase: `${API_ROOT}/cryptographic-failures`,
    Component: CryptographicFailures,
  },
  {
    rank: 5,
    code: 'A05',
    slug: 'injection',
    path: '/web/a05',
    title: 'Injection',
    navTitle: 'Injection',
    description: 'Untrusted input interpreted as a command or query.',
    examples: ['SQL injection', 'Command injection', 'NoSQL / LDAP / template injection'],
    apiBase: `${API_ROOT}/injection`,
    Component: Injection,
  },
  {
    rank: 6,
    code: 'A06',
    slug: 'insecure-design',
    path: '/web/a06',
    title: 'Insecure Design',
    navTitle: 'Insecure Design',
    description: 'Missing or flawed security controls baked into the design itself.',
    examples: ['Missing security controls', 'Business logic flaws', 'No rate limiting'],
    apiBase: `${API_ROOT}/insecure-design`,
    Component: InsecureDesign,
  },
  {
    rank: 7,
    code: 'A07',
    slug: 'authentication-failures',
    path: '/web/a07',
    title: 'Authentication Failures',
    navTitle: 'Authentication Failures',
    description: 'Broken authentication and session management.',
    examples: ['Weak passwords allowed', 'Session hijacking', 'No brute-force protection'],
    apiBase: `${API_ROOT}/authentication-failures`,
    Component: AuthenticationFailures,
  },
  {
    rank: 8,
    code: 'A08',
    slug: 'data-integrity-failures',
    path: '/web/a08',
    title: 'Software or Data Integrity Failures',
    navTitle: 'Data Integrity Failures',
    description: 'Code and data trusted without verifying integrity.',
    examples: ['Unsigned updates', 'Insecure CI/CD pipelines', 'Untrusted deserialization'],
    apiBase: `${API_ROOT}/data-integrity-failures`,
    Component: DataIntegrityFailures,
  },
  {
    rank: 9,
    code: 'A09',
    slug: 'security-logging-alerting-failures',
    path: '/web/a09',
    title: 'Security Logging and Alerting Failures',
    navTitle: 'Logging & Alerting Failures',
    description: 'Breaches go undetected. Renamed from "Monitoring" to "Alerting" in 2025.',
    examples: ['No audit logs', 'Missing alerts', 'Logs exposing sensitive data'],
    apiBase: `${API_ROOT}/security-logging-alerting-failures`,
    Component: SecurityLoggingFailures,
  },
  {
    rank: 10,
    code: 'A10',
    slug: 'mishandling-exceptional-conditions',
    path: '/web/a10',
    title: 'Mishandling of Exceptional Conditions',
    navTitle: 'Mishandling Exceptions',
    description:
      'New for 2025: unsafe error handling that leaks internals or fails open.',
    examples: ['Leaked stack traces', 'Verbose database errors', 'Fail-open on exception'],
    apiBase: `${API_ROOT}/mishandling-exceptional-conditions`,
    Component: MishandlingExceptionalConditions,
  },
];

export type { WebVuln, WebVulnProps } from './types';
