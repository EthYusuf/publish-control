// ═══════════════════════════════════════════════════════════════
// Publish Control — Server Configuration Analyzer
// Audits server interface binding, debug flags, and headers.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { SERVER_CONFIG_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class ServerAnalyzer extends BaseAnalyzer {
  readonly name = 'server';
  readonly displayName = 'Server Configuration Audit';
  readonly emoji = '🌐';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const sourceFiles = this.getSourceFiles(context);
    let findingIndex = 0;

    let hasHelmet = false;

    // Check package.json dependencies for helmet
    if (context.packageJson) {
      const deps = {
        ...(context.packageJson.dependencies as Record<string, string> || {}),
        ...(context.packageJson.devDependencies as Record<string, string> || {}),
      };
      if ('helmet' in deps) {
        hasHelmet = true;
      }
    }

    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;

      const content = readFileContent(file.path);
      if (!content) continue;

      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        if (this.isCommentLine(trimmed)) continue;

        for (const pattern of SERVER_CONFIG_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `SRV-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.HIGH,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation: this.getServerRecommendation(pattern.name),
              owasp: 'A05:2021 - Security Misconfiguration',
              cwe: 'CWE-16: Configuration',
            });
            break;
          }
        }
      }
    }

    // If it's an express/fastify/koa project and helmet is missing
    if (
      (context.framework === 'express' || context.framework === 'koa') &&
      !hasHelmet
    ) {
      findingIndex++;
      findings.push({
        id: `SRV-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.MEDIUM,
        title: 'Missing Security Headers Middleware (Helmet)',
        description:
          'Projede Express/Koa tespit edildi fakat HTTP güvenlik başlıklarını (HSTS, CSP, X-Frame-Options vb.) yöneten `helmet` paketi bulunamadı.',
        recommendation:
          '`npm install helmet` kurun ve uygulamanın başında `app.use(helmet())` olarak entegre edin.',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }

    return findings;
  }

  private getServerRecommendation(name: string): string {
    if (name.includes('0.0.0.0')) {
      return 'Geliştirme ortamında veya ters vekil (reverse proxy) arkasında sunucuyu `127.0.0.1` adresine bağlayın. Açık internete doğrudan sunucu portu açmaktan kaçının.';
    }
    if (name.includes('Debug')) {
      return 'Canlı (production) ortamında hata ayıklama (debug) bayraklarını kapatın; ayrıntılı hata dökümleri saldırganlara bilgi sızdırabilir.';
    }
    if (name.includes('Introspection')) {
      return 'Canlı ortamda GraphQL Introspection özelliğini devre dışı bırakın (Apollo Server vb. `introspection: false`).';
    }
    return 'Sunucu yapılandırmasını kurumsal güvenlik ilkelerine uygun hale getirin.';
  }
}
