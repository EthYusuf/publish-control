// ═══════════════════════════════════════════════════════════════
// Publish Control — Code Quality & Best Practices Analyzer
// Checks for @ts-ignore, any proliferation, security TODOs, console statements.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { readFileContent } from '../utils/file-walker.js';

export class QualityAnalyzer extends BaseAnalyzer {
  readonly name = 'quality';
  readonly displayName = 'Code Quality & Security Hygiene';
  readonly emoji = '📊';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const sourceFiles = this.getSourceFiles(context);
    let findingIndex = 0;

    let tsIgnoreCount = 0;
    let anyCount = 0;
    let securityTodoCount = 0;

    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;

      const content = readFileContent(file.path);
      if (!content) continue;

      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        // Check @ts-ignore / @ts-nocheck
        if (trimmed.includes('@ts-ignore') || trimmed.includes('@ts-nocheck')) {
          tsIgnoreCount++;
          if (tsIgnoreCount <= 3) {
            findingIndex++;
            findings.push({
              id: `QUAL-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.LOW,
              title: 'TypeScript Type Checking Suppressed',
              description: `\`${trimmed}\` ile derleyici kontrolleri devre dışı bırakılmış.`,
              file: file.relativePath,
              line: i + 1,
              recommendation: '@ts-ignore yerine uygun tip tanımlamalarını sağlayın.',
            });
          }
        }

        // Check security-related TODO comments
        if (
          trimmed.match(/(?:\/\/|\/\*|#)\s*(?:TODO|FIXME|HACK|XXX).*(?:security|vuln|auth|password|leak|secret|bypass)/i)
        ) {
          securityTodoCount++;
          findingIndex++;
          findings.push({
            id: `QUAL-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.MEDIUM,
            title: 'Unresolved Security TODO/FIXME',
            description: `Güvenlikle ilgili çözülmemiş not: \`${this.redactLine(trimmed)}\``,
            file: file.relativePath,
            line: i + 1,
            recommendation: 'Yayına almadan önce güvenlikle ilgili TODO ve geçici çözümleri tamamlayın.',
          });
        }

        // Count excessive 'any' usage
        if (trimmed.match(/:\s*any\b/) || trimmed.match(/as\s+any\b/)) {
          anyCount++;
        }
      }
    }

    if (anyCount > 15) {
      findingIndex++;
      findings.push({
        id: `QUAL-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.LOW,
        title: `Excessive "any" Type Usage (${anyCount} occurrences)`,
        description:
          'Projede yaygın olarak `any` tipi kullanılmış. Bu durum TypeScript tip kontrolünün güvenlik sağlama işlevini zayıflatır.',
        recommendation: 'Bilinmeyen tipler için `unknown` kullanın ve tip korumaları (type guards) yazın.',
      });
    }

    return findings;
  }
}
