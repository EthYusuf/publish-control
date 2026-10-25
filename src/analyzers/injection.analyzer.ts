// ═══════════════════════════════════════════════════════════════
// Publish Control — Injection Analyzer
// Detects SQL, NoSQL, Command, and Cross-Site Scripting (XSS) injection.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { INJECTION_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class InjectionAnalyzer extends BaseAnalyzer {
  readonly name = 'injection';
  readonly displayName = 'Injection Vulnerabilities';
  readonly emoji = '💉';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const sourceFiles = this.getSourceFiles(context);
    let findingIndex = 0;

    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;

      const content = readFileContent(file.path);
      if (!content) continue;

      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        if (this.isCommentLine(trimmed)) continue;

        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            const isCritical =
              pattern.name.includes('SQL') ||
              pattern.name.includes('child_process') ||
              pattern.name.includes('eval');

            findings.push({
              id: `INJ-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: isCritical ? Severity.CRITICAL : Severity.HIGH,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation: this.getInjectionRecommendation(pattern.name),
              owasp: isCritical ? 'A03:2021 - Injection' : 'A03:2021 - Injection / XSS',
              cwe: pattern.name.includes('SQL')
                ? 'CWE-89: SQL Injection'
                : pattern.name.includes('exec') || pattern.name.includes('eval')
                ? 'CWE-78: Command Injection'
                : 'CWE-79: Cross-site Scripting',
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  private getInjectionRecommendation(name: string): string {
    if (name.includes('SQL')) {
      return 'Parametreli sorgular (parameterized queries/prepared statements) veya güvenli bir ORM kullanın. Sorgu stringiyle kullanıcı girdisini asla birleştirmeyin.';
    }
    if (name.includes('eval') || name.includes('Function')) {
      return 'eval() ve Function kurucusunu dinamik kod çalıştırmak için kullanmayın. Güvenli ayrıştırma kütüphaneleri (JSON.parse vb.) tercih edin.';
    }
    if (name.includes('exec')) {
      return 'Kullanıcı girdisini shell komutuna doğrudan vermeyin. `execFile` veya parametre dizisi alan `spawn` fonksiyonlarını kullanın.';
    }
    if (name.includes('innerHTML') || name.includes('dangerouslySetInnerHTML')) {
      return 'Kullanıcı girdisini doğrudan DOM öğelerine basmayın. DOMPurify ile sanitize edin veya textContent/güvenli framework render mekanizmalarını kullanın.';
    }
    return 'Girdiyi işlemeden önce katı şema doğrulaması (ör. Zod) yapın ve veriyi bağlama göre sanitize edin.';
  }
}
