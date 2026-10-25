// ═══════════════════════════════════════════════════════════════
// Publish Control — Core Type Definitions
// ═══════════════════════════════════════════════════════════════

/**
 * Severity levels for security findings.
 */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

/**
 * Numeric weight for each severity level (used for score calculations).
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 25,
  [Severity.HIGH]: 15,
  [Severity.MEDIUM]: 8,
  [Severity.LOW]: 3,
};

/**
 * A single security finding produced by an analyzer.
 */
export interface Finding {
  /** Unique finding identifier (e.g., SEC-001) */
  id: string;
  /** Name of the analyzer that produced this finding */
  analyzer: string;
  /** Severity level */
  severity: Severity;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** File path (relative to project root) */
  file?: string;
  /** Line number within the file */
  line?: number;
  /** Relevant code snippet (redacted if needed) */
  code?: string;
  /** Recommended fix */
  recommendation: string;
  /** OWASP reference (e.g., A07:2021) */
  owasp?: string;
  /** CWE reference (e.g., CWE-798) */
  cwe?: string;
}

/**
 * Result from a single analyzer module.
 */
export interface AnalyzerResult {
  /** Internal analyzer name */
  analyzerName: string;
  /** Human-readable display name */
  displayName: string;
  /** Emoji icon */
  emoji: string;
  /** All findings from this analyzer */
  findings: Finding[];
  /** Security score 0-100 (100 = no issues) */
  score: number;
  /** Execution time in milliseconds */
  executionTimeMs: number;
}

/**
 * The complete security report.
 */
export interface SecurityReport {
  /** Project name (from package.json or directory name) */
  projectName: string;
  /** Absolute path to the project */
  projectPath: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Overall security score 0-100 */
  overallScore: number;
  /** Total number of findings */
  totalFindings: number;
  /** Count by severity */
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  /** Individual analyzer results */
  results: AnalyzerResult[];
  /** Markdown summary */
  summary: string;
}

/**
 * Context about the project being analyzed.
 */
export interface ProjectContext {
  /** Absolute path to project root */
  rootPath: string;
  /** All scanned files */
  files: FileInfo[];
  /** Parsed package.json (if present) */
  packageJson?: Record<string, unknown>;
  /** Whether a Dockerfile exists */
  hasDocker: boolean;
  /** Whether .env file(s) exist */
  hasEnvFile: boolean;
  /** Whether tsconfig.json exists */
  hasTsConfig: boolean;
  /** Detected framework (express, nextjs, nestjs, etc.) */
  framework?: string;
  /** Primary language */
  language: 'typescript' | 'javascript' | 'mixed' | 'unknown';
  /** Whether .gitignore exists */
  hasGitignore: boolean;
  /** Contents of .gitignore */
  gitignorePatterns: string[];
}

/**
 * Information about a single file in the project.
 */
export interface FileInfo {
  /** Absolute path */
  path: string;
  /** Path relative to project root */
  relativePath: string;
  /** File extension (e.g., ".ts") */
  extension: string;
  /** File size in bytes */
  size: number;
}

/**
 * Options for controlling the analysis.
 */
export interface AnalysisOptions {
  /** Only run specific analyzer categories */
  categories?: string[];
  /** Minimum severity filter */
  severity?: string;
  /** Maximum number of files to scan */
  maxFiles?: number;
}
