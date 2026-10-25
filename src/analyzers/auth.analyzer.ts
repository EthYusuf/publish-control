// ═══════════════════════════════════════════════════════════════
// Publish Control — Authentication & Authorization Analyzer
// Detects broken access control, weak hashing, and flawed JWT settings.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { AUTH_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class AuthAnalyzer extends BaseAnalyzer {
  readonly name = 'auth';
  readonly displayName = 'Authentication & Authorization';
  readonly emoji = '🔒';

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

        for (const pattern of AUTH_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            const isCritical = pattern.name.includes('None') || pattern.name.includes('Hardcoded JWT');

            findings.push({
              id: `AUTH-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: isCritical ? Severity.CRITICAL : Severity.HIGH,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation: this.getAuthRecommendation(pattern.name),
              owasp: 'A07:2021 - Identification and Authentication Failures',
              cwe: pattern.name.includes('Hashing')
                ? 'CWE-328: Use of Weak Hash'
                : 'CWE-287: Improper Authentication',
            });
            break;
          }
        }

        // Check for missing auth middleware on sensitive Express routes
        if (
          trimmed.match(/app\.(?:post|put|delete|patch)\s*\(\s*['"]\/(?:admin|api\/users|api\/settings|api\/delete)/) &&
          !trimmed.includes('auth') &&
          !trimmed.includes('verify') &&
          !trimmed.includes('protect') &&
          !trimmed.includes('passport')
        ) {
          findingIndex++;
          findings.push({
            id: `AUTH-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Potentially Unprotected Sensitive Route',
            description: `Hassas endpoint için kimlik doğrulama middleware'i görünmüyor: \`${this.redactLine(trimmed)}\``,
            file: file.relativePath,
            line: i + 1,
            recommendation:
              'Hassas yönetimsel veya veri değiştirici API rotalarını yetkilendirme middleware (ör. authenticateToken, requireRole) ile koruyun.',
            owasp: 'A01:2021 - Broken Access Control',
            cwe: 'CWE-306: Missing Authentication for Critical Function',
          });
        }
      }
    }

    return findings;
  }

  private getAuthRecommendation(name: string): string {
    if (name.includes('None')) {
      return 'JWT doğrulamasında "none" algoritmasını kesinlikle reddedin. HS256 veya RS256/ES256 gibi güçlü şifreleme algoritmaları zorunlu kılın.';
    }
    if (name.includes('Hashing')) {
      return 'Parolalar için MD5 veya SHA1 kullanmayın. Argon2id veya bcrypt (work factor >= 12) kullanın.';
    }
    if (name.includes('JWT Secret')) {
      return 'JWT gizli imza anahtarını kaynak kodda tutmayın. En az 256-bit entropiye sahip bir değeri process.env üzerinden temin edin.';
    }
    return 'Kimlik doğrulama standartlarına ve güncel güvenlik kütüphanelerine uyun.';
  }
}
