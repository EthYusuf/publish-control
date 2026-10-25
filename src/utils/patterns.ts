// ═══════════════════════════════════════════════════════════════
// Publish Control — Regex Pattern Collections
// ═══════════════════════════════════════════════════════════════

/**
 * A named regex pattern with metadata.
 */
export interface SecurityPattern {
  /** Pattern identifier */
  name: string;
  /** The regex to test against */
  regex: RegExp;
  /** Human-readable description */
  description: string;
}

// ─── Secrets Detection Patterns ──────────────────────────────

export const SECRET_PATTERNS: SecurityPattern[] = [
  {
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/,
    description: 'AWS Access Key ID detected',
  },
  {
    name: 'AWS Secret Key',
    regex: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/i,
    description: 'AWS Secret Access Key detected',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[a-zA-Z0-9]{36}/,
    description: 'GitHub Personal Access Token detected',
  },
  {
    name: 'GitHub OAuth Token',
    regex: /gho_[a-zA-Z0-9]{36}/,
    description: 'GitHub OAuth Access Token detected',
  },
  {
    name: 'GitHub App Token',
    regex: /(?:ghs|ghr)_[a-zA-Z0-9]{36}/,
    description: 'GitHub App or Refresh Token detected',
  },
  {
    name: 'GitHub Fine-grained PAT',
    regex: /github_pat_[a-zA-Z0-9_]{22,}/,
    description: 'GitHub Fine-grained Personal Access Token detected',
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/,
    description: 'Google API Key detected',
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,99}/,
    description: 'Stripe Live Secret Key detected',
  },
  {
    name: 'Stripe Live Publishable Key',
    regex: /pk_live_[0-9a-zA-Z]{24,99}/,
    description: 'Stripe Live Publishable Key detected',
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/,
    description: 'Slack Token detected',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,
    description: 'Slack Webhook URL detected',
  },
  {
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/,
    description: 'JWT Token detected in source code',
  },
  {
    name: 'SSH Private Key',
    regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----/,
    description: 'Private SSH/RSA key detected',
  },
  {
    name: 'Generic Password Assignment',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    description: 'Hardcoded password assignment detected',
  },
  {
    name: 'Generic Secret Assignment',
    regex: /(?:secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-/.+]{12,}['"]/i,
    description: 'Hardcoded secret or API key assignment detected',
  },
  {
    name: 'MongoDB Connection String',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/i,
    description: 'MongoDB connection string with credentials detected',
  },
  {
    name: 'PostgreSQL/MySQL Connection String',
    regex: /(?:postgres|mysql|mariadb):\/\/[^:]+:[^@]+@[^\s'"]+/i,
    description: 'Database connection string with credentials detected',
  },
  {
    name: 'Firebase Config',
    regex: /(?:firebase|supabase).*(?:apiKey|anonKey)\s*[:=]\s*['"][^'"]+['"]/i,
    description: 'Firebase/Supabase configuration key detected',
  },
  {
    name: 'SendGrid API Key',
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
    description: 'SendGrid API Key detected',
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:twilio).*(?:auth_token|token)\s*[:=]\s*['"][a-f0-9]{32}['"]/i,
    description: 'Twilio Auth Token detected',
  },
  {
    name: 'OpenAI API Key',
    regex: /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/,
    description: 'OpenAI API Key detected',
  },
  {
    name: 'Bearer Token Hardcoded',
    regex: /['"]Bearer\s+[a-zA-Z0-9_\-/.+=]{20,}['"]/,
    description: 'Hardcoded Bearer token detected',
  },
];

// ─── Injection Patterns ──────────────────────────────────────

export const INJECTION_PATTERNS: SecurityPattern[] = [
  {
    name: 'SQL String Concatenation',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*['"`]\s*\+\s*(?:req\.|params\.|query\.|body\.|args)/i,
    description: 'SQL query using string concatenation with user input',
  },
  {
    name: 'SQL Template Literal',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\$\{(?:req\.|params\.|query\.|body\.|args|input|user)/i,
    description: 'SQL query using template literal with user input',
  },
  {
    name: 'eval() Usage',
    regex: /\beval\s*\(/,
    description: 'Use of eval() — potential code injection',
  },
  {
    name: 'Function Constructor',
    regex: /new\s+Function\s*\(/,
    description: 'Use of Function constructor — potential code injection',
  },
  {
    name: 'child_process exec with input',
    regex: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    description: 'Shell command execution with potentially unsanitized input',
  },
  {
    name: 'MongoDB $where',
    regex: /\$where\s*:/,
    description: 'MongoDB $where operator — potential NoSQL injection',
  },
  {
    name: 'MongoDB $regex with user input',
    regex: /\$regex\s*:\s*(?:req\.|params\.|query\.|body\.)/,
    description: 'MongoDB $regex with user-controlled input',
  },
  {
    name: 'innerHTML assignment',
    regex: /\.innerHTML\s*=\s*(?!['"]<)/,
    description: 'innerHTML assignment with dynamic content — XSS risk',
  },
  {
    name: 'dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML/,
    description: 'React dangerouslySetInnerHTML — XSS risk',
  },
  {
    name: 'document.write',
    regex: /document\.write\s*\(/,
    description: 'document.write() usage — XSS risk',
  },
];

// ─── Server Configuration Patterns ───────────────────────────

export const SERVER_CONFIG_PATTERNS: SecurityPattern[] = [
  {
    name: 'Bind All Interfaces',
    regex: /(?:listen|bind|host)\s*\(\s*['"]0\.0\.0\.0['"]/,
    description: 'Server binding to all network interfaces (0.0.0.0)',
  },
  {
    name: 'Debug Mode in Production',
    regex: /(?:debug|DEBUG)\s*[:=]\s*(?:true|1|['"]true['"])/,
    description: 'Debug mode potentially enabled in production',
  },
  {
    name: 'GraphQL Introspection',
    regex: /introspection\s*:\s*true/,
    description: 'GraphQL introspection enabled — information disclosure risk',
  },
];

// ─── Auth Patterns ───────────────────────────────────────────

export const AUTH_PATTERNS: SecurityPattern[] = [
  {
    name: 'JWT Algorithm None',
    regex: /algorithm[s]?\s*[:=]\s*['"]none['"]/i,
    description: 'JWT using "none" algorithm — signature bypass vulnerability',
  },
  {
    name: 'Weak Hashing (MD5)',
    regex: /(?:createHash|hash)\s*\(\s*['"]md5['"]/i,
    description: 'MD5 hashing detected — cryptographically weak',
  },
  {
    name: 'Weak Hashing (SHA1)',
    regex: /(?:createHash|hash)\s*\(\s*['"]sha1?['"]/i,
    description: 'SHA1 hashing detected — cryptographically weak for passwords',
  },
  {
    name: 'Hardcoded JWT Secret',
    regex: /(?:jwt|token).*(?:secret|key)\s*[:=]\s*['"][^'"]{4,}['"]/i,
    description: 'JWT secret appears to be hardcoded',
  },
];

// ─── SSRF Patterns ───────────────────────────────────────────

export const SSRF_PATTERNS: SecurityPattern[] = [
  {
    name: 'User-controlled URL fetch',
    regex: /(?:fetch|axios|got|request|http\.get|https\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.|args|input|url)/,
    description: 'HTTP request with user-controlled URL — SSRF risk',
  },
  {
    name: 'Internal IP Access',
    regex: /(?:127\.0\.0\.1|169\.254\.169\.254|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)/,
    description: 'Reference to internal/loopback IP address',
  },
];

// ─── Path Traversal Patterns ─────────────────────────────────

export const PATH_TRAVERSAL_PATTERNS: SecurityPattern[] = [
  {
    name: 'Unsanitized path.join',
    regex: /path\.(?:join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.|input|user)/,
    description: 'path.join/resolve with user-controlled input — path traversal risk',
  },
  {
    name: 'fs operations with user input',
    regex: /fs\.(?:readFile|writeFile|readFileSync|writeFileSync|unlink|unlinkSync|createReadStream)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/,
    description: 'File system operation with user-controlled path',
  },
  {
    name: 'sendFile with user input',
    regex: /(?:res\.sendFile|res\.download)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/,
    description: 'res.sendFile/download with user-controlled path',
  },
];

// ─── CORS Patterns ───────────────────────────────────────────

export const CORS_PATTERNS: SecurityPattern[] = [
  {
    name: 'Wildcard CORS Origin',
    regex: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"]\*['"]/,
    description: 'CORS configured with wildcard origin (*)',
  },
  {
    name: 'CORS Origin True',
    regex: /origin\s*:\s*true/,
    description: 'CORS origin set to true — reflects all origins',
  },
  {
    name: 'CORS Credentials with Wildcard',
    regex: /credentials\s*:\s*true/,
    description: 'CORS credentials enabled — check if combined with wildcard origin',
  },
];

// ─── TLS/HTTPS Patterns ─────────────────────────────────────

export const TLS_PATTERNS: SecurityPattern[] = [
  {
    name: 'Reject Unauthorized Disabled',
    regex: /rejectUnauthorized\s*:\s*false/,
    description: 'TLS certificate validation disabled — MITM risk',
  },
  {
    name: 'TLS Reject Env Variable',
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/,
    description: 'NODE_TLS_REJECT_UNAUTHORIZED set to 0 — disables TLS validation',
  },
];

// ─── Docker Patterns ─────────────────────────────────────────

export const DOCKER_PATTERNS: SecurityPattern[] = [
  {
    name: 'Docker Root User',
    regex: /^\s*USER\s+root\s*$/m,
    description: 'Container running as root user',
  },
  {
    name: 'Docker Latest Tag',
    regex: /^\s*FROM\s+\S+:latest\s*$/m,
    description: 'Using :latest tag — non-deterministic builds',
  },
  {
    name: 'Docker Privileged',
    regex: /privileged\s*:\s*true/,
    description: 'Container running in privileged mode',
  },
  {
    name: 'Docker ENV Secret',
    regex: /^\s*ENV\s+(?:.*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL).*=\s*\S+)/im,
    description: 'Secret value set in Dockerfile ENV directive',
  },
];

// ─── Logging Patterns ────────────────────────────────────────

export const LOGGING_PATTERNS: SecurityPattern[] = [
  {
    name: 'Logging Password',
    regex: /console\.(?:log|info|warn|error|debug)\s*\([^)]*(?:password|passwd|pwd|secret|token|apiKey|api_key|credentials)/i,
    description: 'Potentially logging sensitive data (password/secret/token)',
  },
  {
    name: 'Logging Request Body',
    regex: /console\.(?:log|info|debug)\s*\(\s*(?:req\.body|request\.body)\s*\)/,
    description: 'Logging entire request body — may contain sensitive data',
  },
];

// ─── Error Handling Patterns ─────────────────────────────────

export const ERROR_HANDLING_PATTERNS: SecurityPattern[] = [
  {
    name: 'Stack Trace Exposure',
    regex: /(?:res\.(?:send|json|status)\s*\([^)]*|response\.).*(?:\.stack|\.message|err\b|error\b)/,
    description: 'Potentially exposing error details/stack traces to clients',
  },
  {
    name: 'Verbose Error Response',
    regex: /catch\s*\([^)]*\)\s*\{[^}]*res\.(?:send|json)\s*\(\s*(?:err|error|e)\s*\)/,
    description: 'Sending raw error object in response — information disclosure',
  },
];

/**
 * Calculate Shannon entropy of a string.
 * High entropy (> 4.5) often indicates secrets/random strings.
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}
