// ═══════════════════════════════════════════════════════════════
// Publish Control — Severity Utilities
// ═══════════════════════════════════════════════════════════════

import { Severity, SEVERITY_WEIGHTS } from '../core/types.js';
import type { Finding } from '../core/types.js';

/**
 * Compare two severity levels. Returns negative if a < b, positive if a > b, 0 if equal.
 */
export function compareSeverity(a: Severity, b: Severity): number {
  const order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL];
  return order.indexOf(a) - order.indexOf(b);
}

/**
 * Check if a finding meets the minimum severity threshold.
 */
export function meetsSeverity(finding: Finding, minSeverity: string): boolean {
  const order: Record<string, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
    all: 0,
  };

  const findingLevel = order[finding.severity.toLowerCase()] ?? 0;
  const threshold = order[minSeverity.toLowerCase()] ?? 0;

  return findingLevel >= threshold;
}

/**
 * Calculate a score (0-100) based on findings and their severities.
 */
export function calculateScore(findings: Finding[]): number {
  let deductions = 0;
  for (const f of findings) {
    deductions += SEVERITY_WEIGHTS[f.severity] ?? 3;
  }
  return Math.max(0, 100 - deductions);
}

/**
 * Get emoji for a severity level.
 */
export function severityEmoji(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL: return '🔴';
    case Severity.HIGH: return '🟠';
    case Severity.MEDIUM: return '🟡';
    case Severity.LOW: return '🔵';
  }
}

/**
 * Sort findings by severity (CRITICAL first).
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => compareSeverity(b.severity, a.severity));
}
