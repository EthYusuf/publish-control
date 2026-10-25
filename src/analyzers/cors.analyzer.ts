// ═══════════════════════════════════════════════════════════════
// Publish Control — CORS Analyzer
// Audits Cross-Origin Resource Sharing configurations.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { CORS_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class CorsAnalyzer extends BaseAnalyzer {
  readonly name = 'cors';
  readonly displayName = 'CORS Misconfiguration';
  readonly emoji = '🛡️';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const sourceFiles = this.getSourceFiles(context);
    let findingIndex = 0;

    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;

      const content = readFileContent(file.path);
      if (!content) continue;

      const lines = content.split('\n');
      let fileHasWildcardOrigin = false;
      let fileHasCredentialsTrue = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        if (this.isCommentLine(trimmed)) continue;

        if (CORS_PATTERNS[0].regex.test(line) || CORS_PATTERNS[1].regex.test(line)) {
          fileHasWildcardOrigin = true;
          findingIndex++;
          findings.push({
            id: `CORS-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Overly Permissive CORS Origin',
            description: 'CORS yapılandırmasında tüm kaynaklara (`*` veya `origin: true`) izin verilmiş.',
            file: file.relativePath,
            line: i + 1,
            code: this.redactLine(trimmed),
            recommendation:
              'CORS için güvenilir alan adlarından oluşan açık bir whitelist (izin listesi) kullanın. Herkese açık API değilse joker karakter (`*`) kullanmaktan kaçının.',
            owasp: 'A05:2021 - Security Misconfiguration',
            cwe: 'CWE-346: Origin Validation Error',
          });
        }

        if (CORS_PATTERNS[2].regex.test(line)) {
          fileHasCredentialsTrue = true;
        }
      }

      if (fileHasWildcardOrigin && fileHasCredentialsTrue) {
        findingIndex++;
        findings.push({
          id: `CORS-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.CRITICAL,
          title: 'CORS Credentials with Permissive Origin',
          description:
            'Aynı dosyada hem `credentials: true` hem de wildcard/yansıtıcı origin tespiti yapıldı. Tarayıcılar bu kombinasyonda cookie çalınmasına ve CSRF türevi saldırılara izin verebilir.',
          file: file.relativePath,
          recommendation:
            'Kimlik bilgisi taşıyan (credentials) isteklerde spesifik ve doğrulanmış alan adları tanımlayın.',
          owasp: 'A05:2021',
          cwe: 'CWE-346',
        });
      }
    }

    return findings;
  }
}
