// ═══════════════════════════════════════════════════════════════
// Publish Control — HTTPS/TLS Analyzer
// Checks SSL/TLS settings, rejection bypasses, and plain HTTP usage.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { TLS_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class HttpsAnalyzer extends BaseAnalyzer {
  readonly name = 'https';
  readonly displayName = 'HTTPS & TLS Security';
  readonly emoji = '🔐';

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

        for (const pattern of TLS_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `TLS-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.CRITICAL,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                'TLS sertifika doğrulamasını asla devre dışı bırakmayın. Yerel geliştirme için dahi `rejectUnauthorized: false` veya `NODE_TLS_REJECT_UNAUTHORIZED=0` kullanmayın, mkcert ile güvenilen yerel sertifika oluşturun.',
              owasp: 'A02:2021 - Cryptographic Failures',
              cwe: 'CWE-295: Improper Certificate Validation',
            });
            break;
          }
        }

        // Detect insecure http:// endpoints in outbound requests
        if (
          trimmed.match(/(?:fetch|axios\.get|axios\.post|http\.request)\s*\(\s*['"]http:\/\//) &&
          !trimmed.includes('localhost') &&
          !trimmed.includes('127.0.0.1')
        ) {
          findingIndex++;
          findings.push({
            id: `TLS-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Insecure Outbound HTTP Request',
            description: `Şifrelenmemiş HTTP protokolü ile dış kaynak çağrısı yapılıyor: \`${this.redactLine(trimmed)}\``,
            file: file.relativePath,
            line: i + 1,
            recommendation: 'Ağ trafiğini şifrelemek ve ortadaki adam (MITM) saldırılarını önlemek için daima HTTPS kullanın.',
            owasp: 'A02:2021',
            cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
          });
        }
      }
    }

    return findings;
  }
}
