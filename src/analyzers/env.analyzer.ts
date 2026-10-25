// ═══════════════════════════════════════════════════════════════
// Publish Control — Environment Security Analyzer
// Checks .env hygiene, .gitignore exclusion, and default fallback secrets.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { readFileContent } from '../utils/file-walker.js';

export class EnvAnalyzer extends BaseAnalyzer {
  readonly name = 'env';
  readonly displayName = 'Environment Security';
  readonly emoji = '📁';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingIndex = 0;

    // 1. Check if .gitignore exists and ignores .env
    const gitignoreCoversEnv = context.gitignorePatterns.some(
      (pat) => pat === '.env' || pat === '*.env' || pat === '.env*' || pat === '.env.*'
    );

    if (context.hasEnvFile && !gitignoreCoversEnv) {
      findingIndex++;
      findings.push({
        id: `ENV-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.CRITICAL,
        title: '.env File Not Ignored by Git',
        description: 'Projede .env dosyası mevcut ancak .gitignore dosyasında engellenmemiş. Hassas bilgiler Git deposuna sızabilir.',
        file: '.gitignore',
        recommendation:
          '.gitignore dosyasına `.env` ve `.env.*` satırlarını ekleyin. Halihazırda git geçmişine girdi ise `git rm --cached .env` çalıştırıp anahtarları derhal revoke edin.',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }

    // 2. Check if .env.example exists when .env is present
    const hasExample = context.files.some(
      (f) => f.relativePath === '.env.example' || f.relativePath === '.env.template'
    );
    if (context.hasEnvFile && !hasExample) {
      findingIndex++;
      findings.push({
        id: `ENV-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.LOW,
        title: 'Missing .env.example Template',
        description: 'Projede .env.example veya .env.template dosyası bulunamadı. Ekip üyeleri ve CI/CD için şablon sağlamak en iyi pratiktir.',
        recommendation: 'Hassas değerleri içermeyen bir `.env.example` şablon dosyası oluşturun.',
        owasp: 'A05:2021',
      });
    }

    // 3. Scan .env files for actual sensitive values committed
    const envFiles = context.files.filter(
      (f) =>
        f.relativePath === '.env' ||
        (f.relativePath.startsWith('.env.') && !f.relativePath.includes('example'))
    );

    for (const envFile of envFiles) {
      const content = readFileContent(envFile.path);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const parts = line.split('=');
        if (parts.length >= 2) {
          const val = parts.slice(1).join('=').trim().replace(/^['"]|['"]$/g, '');
          // Check if value is a real secret instead of placeholder
          const isPlaceholder =
            val === '' ||
            val.includes('your_') ||
            val.includes('change_me') ||
            val.includes('placeholder') ||
            val.includes('test') ||
            val.includes('example') ||
            val.includes('xxx');

          if (!isPlaceholder && val.length > 12) {
            findingIndex++;
            findings.push({
              id: `ENV-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.HIGH,
              title: 'Active Secret in Environment File',
              description: `\`${parts[0]}\` anahtarı için canlı/gerçek olabilecek bir değer atanmış.`,
              file: envFile.relativePath,
              line: i + 1,
              code: `${parts[0]}=[REDACTED]`,
              recommendation:
                'Canlı secret değerlerini repoda tutmayın. CI/CD secret yöneticisi veya güvenli ortam değişkeni enjeksiyonu kullanın.',
              owasp: 'A05:2021',
            });
            break; // Max 1 finding per file to avoid noise
          }
        }
      }
    }

    // 4. Scan source files for hardcoded fallback values in process.env
    const sourceFiles = this.getSourceFiles(context);
    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;
      const content = readFileContent(file.path);
      if (!content) continue;

      const fallbackRegex = /process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*['"]([a-zA-Z0-9_\-/.+=]{8,})['"]/g;
      let match: RegExpExecArray | null;

      while ((match = fallbackRegex.exec(content)) !== null) {
        const fallbackValue = match[1];
        if (
          !fallbackValue.includes('localhost') &&
          !fallbackValue.includes('3000') &&
          !fallbackValue.includes('development') &&
          !fallbackValue.includes('test')
        ) {
          findingIndex++;
          findings.push({
            id: `ENV-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.MEDIUM,
            title: 'Hardcoded Fallback in process.env',
            description: `Ortam değişkeni bulunamadığında fallback olarak sabit dize atanmış: \`${this.redactLine(match[0])}\``,
            file: file.relativePath,
            recommendation:
              'Kritik ortam değişkenleri eksikse varsayılan değer vermek yerine uygulamanın başlatılmasını engelleyen açık bir hata fırlatın.',
            owasp: 'A05:2021',
          });
        }
      }
    }

    return findings;
  }
}
