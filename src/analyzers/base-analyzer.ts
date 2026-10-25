// ═══════════════════════════════════════════════════════════════
// Publish Control — Base Analyzer
// Abstract class that all analyzer modules extend.
// ═══════════════════════════════════════════════════════════════

import type { Finding, AnalyzerResult, ProjectContext } from '../core/types.js';
import { calculateScore } from '../utils/severity.js';
import { readFileContent } from '../utils/file-walker.js';
import type { SecurityPattern } from '../utils/patterns.js';

/**
 * Abstract base class for all security analyzers.
 * Each analyzer must implement the `analyze` method.
 */
export abstract class BaseAnalyzer {
  /** Internal name used as identifier */
  abstract readonly name: string;
  /** Human-readable display name */
  abstract readonly displayName: string;
  /** Emoji icon for display */
  abstract readonly emoji: string;

  /**
   * Perform the security analysis on the given project context.
   * Must be implemented by each analyzer.
   */
  abstract analyze(context: ProjectContext): Promise<Finding[]>;

  /**
   * Run the analyzer and wrap the result with metadata.
   */
  async run(context: ProjectContext): Promise<AnalyzerResult> {
    const start = Date.now();
    let findings: Finding[];

    try {
      findings = await this.analyze(context);
    } catch (error) {
      // If an analyzer crashes, return an empty result rather than breaking the whole scan
      console.error(`[${this.name}] Analyzer error:`, error);
      findings = [];
    }

    const executionTimeMs = Date.now() - start;

    return {
      analyzerName: this.name,
      displayName: this.displayName,
      emoji: this.emoji,
      findings,
      score: calculateScore(findings),
      executionTimeMs,
    };
  }

  // ─── Helper Methods ──────────────────────────────────────────

  /**
   * Scan file contents against a list of regex patterns.
   * Returns findings for each match.
   */
  protected scanFileWithPatterns(
    filePath: string,
    relativePath: string,
    content: string,
    patterns: SecurityPattern[],
    severityLevel: Finding['severity'],
    analyzerName: string,
    idPrefix: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    let findingIndex = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip comment lines to reduce false positives
      if (this.isCommentLine(trimmed)) continue;

      for (const pattern of patterns) {
        if (pattern.regex.test(line)) {
          findingIndex++;
          findings.push({
            id: `${idPrefix}-${String(findingIndex).padStart(3, '0')}`,
            analyzer: analyzerName,
            severity: severityLevel,
            title: pattern.name,
            description: pattern.description,
            file: relativePath,
            line: i + 1,
            code: this.redactLine(trimmed),
            recommendation: this.getDefaultRecommendation(pattern.name),
          });
        }
      }
    }

    return findings;
  }

  /**
   * Read file content with caching support.
   * Uses the file-walker utility to read file contents.
   */
  protected readFile(filePath: string): string {
    return readFileContent(filePath);
  }

  /**
   * Check if a line is a comment (JS/TS/Python/Shell).
   */
  protected isCommentLine(trimmedLine: string): boolean {
    return (
      trimmedLine.startsWith('//') ||
      trimmedLine.startsWith('/*') ||
      trimmedLine.startsWith('*') ||
      trimmedLine.startsWith('#') ||
      trimmedLine.startsWith('"""') ||
      trimmedLine.startsWith("'''")
    );
  }

  /**
   * Redact potentially sensitive values in a code line for display.
   */
  protected redactLine(line: string, maxLength = 80): string {
    // Truncate long lines
    const truncated = line.length > maxLength ? line.substring(0, maxLength) + '...' : line;

    // Redact obvious secret values (anything after = or : that looks like a key)
    return truncated.replace(
      /([:=]\s*['"]?)([a-zA-Z0-9_\-/.+=]{16,})(['"]?)/g,
      '$1[REDACTED]$3',
    );
  }

  /**
   * Get a default recommendation for a pattern match.
   * Can be overridden by subclasses for more specific recommendations.
   */
  protected getDefaultRecommendation(patternName: string): string {
    return `Review and remediate the "${patternName}" finding. See OWASP guidelines for best practices.`;
  }

  /**
   * Filter project files by extension(s).
   */
  protected getFilesByExtension(context: ProjectContext, ...extensions: string[]) {
    return context.files.filter(f => extensions.includes(f.extension));
  }

  /**
   * Get all source code files (JS/TS).
   */
  protected getSourceFiles(context: ProjectContext) {
    return this.getFilesByExtension(context, '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs');
  }

  /**
   * Check if a file is a test file.
   */
  protected isTestFile(relativePath: string): boolean {
    const lower = relativePath.toLowerCase();
    return (
      lower.includes('.test.') ||
      lower.includes('.spec.') ||
      lower.includes('__tests__') ||
      lower.includes('/test/') ||
      lower.includes('/tests/') ||
      lower.startsWith('test/') ||
      lower.startsWith('tests/')
    );
  }
}
