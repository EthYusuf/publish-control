// ═══════════════════════════════════════════════════════════════
// Publish Control — Rate Limiting Analyzer
// Checks for rate limiting on endpoints and anti-brute-force controls.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { readFileContent } from '../utils/file-walker.js';

export class RateLimitAnalyzer extends BaseAnalyzer {
  readonly name = 'rate-limit';
  readonly displayName = 'Rate Limiting & DoS Protection';
  readonly emoji = '⚡';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingIndex = 0;

    let hasRateLimitLib = false;

    if (context.packageJson) {
      const deps = {
        ...(context.packageJson.dependencies as Record<string, string> || {}),
        ...(context.packageJson.devDependencies as Record<string, string> || {}),
      };
      if (
        'express-rate-limit' in deps ||
        'rate-limiter-flexible' in deps ||
        '@nestjs/throttler' in deps ||
        'bottleneck' in deps
      ) {
        hasRateLimitLib = true;
      }
    }

    // Check for web framework without rate limiting
    if (
      (context.framework === 'express' || context.framework === 'nestjs') &&
      !hasRateLimitLib
    ) {
      findingIndex++;
      findings.push({
        id: `RATE-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.MEDIUM,
        title: 'Missing Rate Limiting Protection',
        description:
          'Projede web API çerçevesi bulunmasına rağmen `express-rate-limit` veya `@nestjs/throttler` gibi hız sınırlayıcı kütüphane tespit edilemedi. Brute-force ve DoS saldırılarına açık olabilir.',
        recommendation:
          'API uç noktaları (özellikle /login, /register, /reset-password) için rate limiter uygulayın.',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
    }

    // Check source files for unthrottled auth routes
    const sourceFiles = this.getSourceFiles(context);
    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;
      const content = readFileContent(file.path);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (
          line.match(/app\.(?:post)\s*\(\s*['"]\/(?:api\/)?(?:auth|login|signin|token)/) &&
          !line.includes('limiter') &&
          !line.includes('throttle') &&
          !hasRateLimitLib
        ) {
          findingIndex++;
          findings.push({
            id: `RATE-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Authentication Endpoint Missing Rate Limiter',
            description: `Giriş/kimlik doğrulama rotasında hız sınırlaması (rate limit) middleware'i yok: \`${this.redactLine(line)}\``,
            file: file.relativePath,
            line: i + 1,
            recommendation:
              'Bu uç noktaya dakikada maksimum 5-10 istek sınırı koyarak parola deneme saldırılarını önleyin.',
            owasp: 'A07:2021',
          });
        }
      }
    }

    return findings;
  }
}
