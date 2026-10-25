// ═══════════════════════════════════════════════════════════════
// Publish Control — Report Generator
// Converts SecurityReport into formatted Markdown output.
// ═══════════════════════════════════════════════════════════════

import type { SecurityReport, AnalyzerResult, Finding } from './types.js';
import { Severity } from './types.js';
import { severityEmoji, sortFindings } from '../utils/severity.js';

/**
 * Report generator that converts analysis results into readable formats.
 */
export class Reporter {
  /**
   * Convert a SecurityReport into a formatted Markdown string.
   */
  static toMarkdown(report: SecurityReport): string {
    const lines: string[] = [];

    // ─── Header ──────────────────────────────────────────────
    lines.push('# 🛡️ Publish Control — Güvenlik Raporu');
    lines.push('');
    lines.push(`📅 **Tarih:** ${new Date(report.timestamp).toLocaleString('tr-TR')}`);
    lines.push(`📁 **Proje:** \`${report.projectName}\``);
    lines.push(`📂 **Dizin:** \`${report.projectPath}\``);
    lines.push(`⭐ **Genel Skor:** ${Reporter.scoreBar(report.overallScore)} **${report.overallScore}/100**`);
    lines.push('');

    // ─── Summary Table ───────────────────────────────────────
    lines.push('## 📊 Özet');
    lines.push('');
    lines.push('| Seviye | Bulgu Sayısı |');
    lines.push('|--------|-------------|');
    lines.push(`| 🔴 CRITICAL | **${report.criticalCount}** |`);
    lines.push(`| 🟠 HIGH | **${report.highCount}** |`);
    lines.push(`| 🟡 MEDIUM | **${report.mediumCount}** |`);
    lines.push(`| 🔵 LOW | **${report.lowCount}** |`);
    lines.push(`| **Toplam** | **${report.totalFindings}** |`);
    lines.push('');

    // ─── Critical Alert ──────────────────────────────────────
    if (report.criticalCount > 0) {
      lines.push('> ⚠️ **UYARI:** Projenizde CRITICAL seviye güvenlik bulguları tespit edildi!');
      lines.push('> Bu sorunlar yayına almadan önce mutlaka düzeltilmelidir.');
      lines.push('');
    }

    // ─── Analyzer Results ────────────────────────────────────
    // Show results with findings first, then passed checks
    const withFindings = report.results.filter(r => r.findings.length > 0);
    const passed = report.results.filter(r => r.findings.length === 0);

    for (const result of withFindings) {
      lines.push(Reporter.formatAnalyzerResult(result));
    }

    // ─── Passed Checks ───────────────────────────────────────
    if (passed.length > 0) {
      lines.push('## ✅ Geçen Kontroller');
      lines.push('');
      for (const result of passed) {
        lines.push(`- ${result.emoji} **${result.displayName}** (${result.score}/100) — ✅ Sorun bulunamadı`);
      }
      lines.push('');
    }

    // ─── Execution Info ──────────────────────────────────────
    const totalMs = report.results.reduce((sum, r) => sum + r.executionTimeMs, 0);
    lines.push('---');
    lines.push(`⏱️ Toplam tarama süresi: ${totalMs}ms | 🔍 Taranan modül sayısı: ${report.results.length}`);

    return lines.join('\n');
  }

  /**
   * Format a single analyzer's results.
   */
  private static formatAnalyzerResult(result: AnalyzerResult): string {
    const lines: string[] = [];

    lines.push(`## ${result.emoji} ${result.displayName} — Skor: ${result.score}/100`);
    lines.push('');

    const sorted = sortFindings(result.findings);

    for (const finding of sorted) {
      lines.push(Reporter.formatFinding(finding));
    }

    return lines.join('\n');
  }

  /**
   * Format a single finding.
   */
  private static formatFinding(finding: Finding): string {
    const lines: string[] = [];
    const emoji = severityEmoji(finding.severity);

    lines.push(`### ${emoji} ${finding.id}: ${finding.title} (${finding.severity})`);
    if (finding.file) {
      lines.push(`- **Dosya:** \`${finding.file}${finding.line ? `:${finding.line}` : ''}\``);
    }
    lines.push(`- **Açıklama:** ${finding.description}`);
    if (finding.code) {
      lines.push(`- **Kod:** \`${finding.code}\``);
    }
    lines.push(`- **Öneri:** ${finding.recommendation}`);
    if (finding.owasp) {
      lines.push(`- **OWASP:** ${finding.owasp}`);
    }
    if (finding.cwe) {
      lines.push(`- **CWE:** ${finding.cwe}`);
    }
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Generate a text-based summary for the report.
   */
  static generateSummary(report: SecurityReport): string {
    const parts: string[] = [];

    if (report.overallScore >= 90) {
      parts.push('🎉 Projeniz güvenlik açısından iyi durumda!');
    } else if (report.overallScore >= 70) {
      parts.push('⚡ Projenizde bazı güvenlik iyileştirmeleri önerilir.');
    } else if (report.overallScore >= 50) {
      parts.push('⚠️ Projenizde önemli güvenlik sorunları tespit edildi.');
    } else {
      parts.push('🚨 Projenizde ciddi güvenlik açıkları bulundu! Acil müdahale gereklidir.');
    }

    if (report.criticalCount > 0) {
      parts.push(`${report.criticalCount} adet CRITICAL seviye bulgu var.`);
    }
    if (report.highCount > 0) {
      parts.push(`${report.highCount} adet HIGH seviye bulgu var.`);
    }

    return parts.join(' ');
  }

  /**
   * Create a visual score bar.
   */
  static scoreBar(score: number): string {
    const filled = Math.round(score / 10);
    const empty = 10 - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);

    let color: string;
    if (score >= 90) color = '🟢';
    else if (score >= 70) color = '🟡';
    else if (score >= 50) color = '🟠';
    else color = '🔴';

    return `${color} [${bar}]`;
  }
}
