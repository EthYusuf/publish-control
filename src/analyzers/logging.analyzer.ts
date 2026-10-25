// ═══════════════════════════════════════════════════════════════
// Publish Control — Logging Analyzer
// Audits logs for passwords, secrets, PII, and request dumps.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { LOGGING_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class LoggingAnalyzer extends BaseAnalyzer {
  readonly name = 'logging';
  readonly displayName = 'Logging & Sensitive Data Leakage';
  readonly emoji = '📝';

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

        for (const pattern of LOGGING_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `LOG-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: pattern.name.includes('Password') ? Severity.HIGH : Severity.MEDIUM,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                'Kullanıcı şifreleri, API anahtarları, kredi kartları veya kimlik bilgilerini loglara yazdırmayın. Loglayıcı katmanında hassas alanları maskeleyin (redaction).',
              owasp: 'A09:2021 - Security Logging and Monitoring Failures',
              cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}
