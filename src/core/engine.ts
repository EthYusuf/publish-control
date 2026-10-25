// ═══════════════════════════════════════════════════════════════
// Publish Control — Analysis Engine
// Orchestrates all analyzers and produces the final report.
// ═══════════════════════════════════════════════════════════════

import type { SecurityReport, AnalyzerResult, AnalysisOptions } from './types.js';
import { Severity } from './types.js';
import { scanProject } from './scanner.js';
import { BaseAnalyzer } from '../analyzers/base-analyzer.js';

// Import all analyzers
import { SecretsAnalyzer } from '../analyzers/secrets.analyzer.js';
import { EnvAnalyzer } from '../analyzers/env.analyzer.js';
import { InjectionAnalyzer } from '../analyzers/injection.analyzer.js';
import { AuthAnalyzer } from '../analyzers/auth.analyzer.js';
import { ServerAnalyzer } from '../analyzers/server.analyzer.js';
import { CorsAnalyzer } from '../analyzers/cors.analyzer.js';
import { HttpsAnalyzer } from '../analyzers/https.analyzer.js';
import { PathTraversalAnalyzer } from '../analyzers/path.analyzer.js';
import { SsrfAnalyzer } from '../analyzers/ssrf.analyzer.js';
import { DockerAnalyzer } from '../analyzers/docker.analyzer.js';
import { DepsAnalyzer } from '../analyzers/deps.analyzer.js';
import { RateLimitAnalyzer } from '../analyzers/rate-limit.analyzer.js';
import { PermissionsAnalyzer } from '../analyzers/permissions.analyzer.js';
import { ErrorHandlingAnalyzer } from '../analyzers/error.analyzer.js';
import { LoggingAnalyzer } from '../analyzers/logging.analyzer.js';
import { ConfigAnalyzer } from '../analyzers/config.analyzer.js';
import { QualityAnalyzer } from '../analyzers/quality.analyzer.js';
import { Reporter } from './reporter.js';

/**
 * The main analysis engine that runs all security analyzers.
 */
export class AnalysisEngine {
  private analyzers: BaseAnalyzer[];

  constructor() {
    this.analyzers = [
      // Critical
      new SecretsAnalyzer(),
      new EnvAnalyzer(),
      new InjectionAnalyzer(),
      new AuthAnalyzer(),
      new ServerAnalyzer(),
      // Medium
      new CorsAnalyzer(),
      new HttpsAnalyzer(),
      new PathTraversalAnalyzer(),
      new SsrfAnalyzer(),
      new DockerAnalyzer(),
      new DepsAnalyzer(),
      // Complementary
      new RateLimitAnalyzer(),
      new PermissionsAnalyzer(),
      new ErrorHandlingAnalyzer(),
      new LoggingAnalyzer(),
      new ConfigAnalyzer(),
      new QualityAnalyzer(),
    ];
  }

  /**
   * Run all (or filtered) analyzers against a project.
   */
  async analyze(projectPath: string, options?: AnalysisOptions): Promise<SecurityReport> {
    // Scan the project to build context
    const context = scanProject(projectPath);

    // Filter analyzers by category if specified
    let activeAnalyzers = this.analyzers;
    if (options?.categories && options.categories.length > 0) {
      const cats = new Set(options.categories.map(c => c.toLowerCase()));
      activeAnalyzers = this.analyzers.filter(a => cats.has(a.name.toLowerCase()));
    }

    // Run all analyzers in parallel
    const results: AnalyzerResult[] = await Promise.all(
      activeAnalyzers.map(analyzer => analyzer.run(context)),
    );

    // Filter findings by severity if specified
    if (options?.severity && options.severity !== 'all') {
      const minSeverityOrder: Record<string, number> = {
        low: 0,
        medium: 1,
        high: 2,
        critical: 3,
      };
      const threshold = minSeverityOrder[options.severity.toLowerCase()] ?? 0;

      for (const result of results) {
        result.findings = result.findings.filter(f => {
          const level = minSeverityOrder[f.severity.toLowerCase()] ?? 0;
          return level >= threshold;
        });
      }
    }

    // Aggregate counts
    let totalFindings = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const result of results) {
      for (const finding of result.findings) {
        totalFindings++;
        switch (finding.severity) {
          case Severity.CRITICAL: criticalCount++; break;
          case Severity.HIGH: highCount++; break;
          case Severity.MEDIUM: mediumCount++; break;
          case Severity.LOW: lowCount++; break;
        }
      }
    }

    // Calculate overall score (weighted average of individual scores)
    const overallScore = results.length > 0
      ? Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length)
      : 100;

    // Determine project name
    const projectName =
      (context.packageJson?.name as string) ||
      context.rootPath.split(/[/\\]/).pop() ||
      'unknown';

    const report: SecurityReport = {
      projectName,
      projectPath: context.rootPath,
      timestamp: new Date().toISOString(),
      overallScore,
      totalFindings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      results,
      summary: '', // Will be filled by reporter
    };

    // Generate summary
    report.summary = Reporter.generateSummary(report);

    return report;
  }

  /**
   * Suggest a fix for a specific finding.
   */
  async suggestFix(findingId: string, projectPath: string): Promise<string> {
    const context = scanProject(projectPath);

    // Run all analyzers to find the specific finding
    const results = await Promise.all(
      this.analyzers.map(a => a.run(context)),
    );

    for (const result of results) {
      for (const finding of result.findings) {
        if (finding.id === findingId) {
          return this.generateFixSuggestion(finding);
        }
      }
    }

    return `Finding "${findingId}" not found. Please run a full scan first.`;
  }

  /**
   * Generate detailed fix suggestion for a finding.
   */
  private generateFixSuggestion(finding: import('./types.js').Finding): string {
    const lines: string[] = [
      `## 🔧 Fix Suggestion: ${finding.id}`,
      '',
      `**${finding.title}** (${finding.severity})`,
      '',
      `**File:** ${finding.file || 'N/A'}${finding.line ? `:${finding.line}` : ''}`,
      '',
      `### Problem`,
      finding.description,
      '',
      `### Recommendation`,
      finding.recommendation,
      '',
    ];

    if (finding.owasp) {
      lines.push(`### References`);
      lines.push(`- OWASP: ${finding.owasp}`);
    }
    if (finding.cwe) {
      lines.push(`- CWE: ${finding.cwe}`);
    }

    return lines.join('\n');
  }
}
