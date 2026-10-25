// ═══════════════════════════════════════════════════════════════
// Publish Control — SSRF Analyzer
// Detects Server-Side Request Forgery vulnerabilities.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { SSRF_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class SsrfAnalyzer extends BaseAnalyzer {
  readonly name = 'ssrf';
  readonly displayName = 'SSRF Detection';
  readonly emoji = '🌍';

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

        // Pattern 1: HTTP requests driven directly by request params
        if (SSRF_PATTERNS[0].regex.test(line)) {
          findingIndex++;
          findings.push({
            id: `SSRF-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Potential SSRF via User URL Input',
            description: `Kullanıcı kontrollü parametre ile HTTP isteği gönderiliyor: \`${this.redactLine(trimmed)}\``,
            file: file.relativePath,
            line: i + 1,
            code: this.redactLine(trimmed),
            recommendation:
              'URL hedeflerini katı bir izin verilenler listesine (domain allowlist) göre doğrulayın. Özel IP bloklarına (10.x, 192.168.x, 169.254.x ve 127.0.0.1) yapılan istekleri engelleyin.',
            owasp: 'A10:2021 - Server-Side Request Forgery (SSRF)',
            cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
          });
        }

        // Pattern 2: Cloud metadata endpoint explicit call
        if (line.includes('169.254.169.254')) {
          findingIndex++;
          findings.push({
            id: `SSRF-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.CRITICAL,
            title: 'AWS/Cloud Metadata Endpoint Reference',
            description: 'Kod içerisinde doğrudan bulut metadata IP adresi (169.254.169.254) referans verilmiş.',
            file: file.relativePath,
            line: i + 1,
            code: this.redactLine(trimmed),
            recommendation:
              'IMDSv2 oturum tokenı gerektirin veya koddan doğrudan metadata sorgulamak yerine resmi AWS/GCP SDK kimlik sağlayıcılarını kullanın.',
            owasp: 'A10:2021',
            cwe: 'CWE-918',
          });
        }
      }
    }

    return findings;
  }
}
