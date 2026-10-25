// ═══════════════════════════════════════════════════════════════
// Publish Control — Docker & Container Security Analyzer
// Audits Dockerfiles and docker-compose configurations.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { DOCKER_PATTERNS } from '../utils/patterns.js';
import { readFileContent, fileExists } from '../utils/file-walker.js';
import * as path from 'node:path';

export class DockerAnalyzer extends BaseAnalyzer {
  readonly name = 'docker';
  readonly displayName = 'Docker & Container Security';
  readonly emoji = '🐳';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingIndex = 0;

    if (!context.hasDocker) {
      return findings; // Skip if project doesn't use Docker
    }

    const dockerfiles = context.files.filter(
      (f) =>
        f.relativePath === 'Dockerfile' ||
        f.relativePath.endsWith('.dockerfile') ||
        f.relativePath.startsWith('Dockerfile.')
    );

    // 1. Check if .dockerignore exists
    const hasDockerignore = fileExists(path.join(context.rootPath, '.dockerignore'));
    if (dockerfiles.length > 0 && !hasDockerignore) {
      findingIndex++;
      findings.push({
        id: `DOCK-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.MEDIUM,
        title: 'Missing .dockerignore File',
        description:
          'Dockerfile mevcut ancak .dockerignore dosyası bulunamadı. `.git`, `.env` ve `node_modules` dizinleri yanlışlıkla container imajına kopyalanabilir.',
        recommendation:
          'Kök dizinde `.dockerignore` oluşturup içine `.git`, `node_modules`, `.env`, `.env.*` vb. ekleyin.',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }

    // 2. Audit each Dockerfile
    for (const dfile of dockerfiles) {
      const content = readFileContent(dfile.path);
      if (!content) continue;

      const lines = content.split('\n');
      let hasUserDirective = false;
      let hasHealthcheck = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        if (trimmed.startsWith('#')) continue;

        if (trimmed.startsWith('USER ')) {
          hasUserDirective = true;
          if (trimmed === 'USER root' || trimmed === 'USER 0') {
            findingIndex++;
            findings.push({
              id: `DOCK-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.HIGH,
              title: 'Container Explicitly Running as Root',
              description: 'Dockerfile içinde `USER root` direktifi verilmiş.',
              file: dfile.relativePath,
              line: i + 1,
              recommendation:
                'Güvenlik için düşük yetkili bir kullanıcı oluşturun ve geçiş yapın: `USER node` veya `USER nonroot`.',
              owasp: 'A05:2021',
            });
          }
        }

        if (trimmed.startsWith('HEALTHCHECK ')) {
          hasHealthcheck = true;
        }

        for (const pattern of DOCKER_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `DOCK-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.MEDIUM,
              title: pattern.name,
              description: pattern.description,
              file: dfile.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                pattern.name.includes('latest')
                  ? 'Determinizm ve stabilite için spesifik imaj tagleri (ör. `node:20.12-alpine`) kullanın.'
                  : 'Docker güvenlik en iyi uygulamalarını takip edin.',
              owasp: 'A05:2021',
            });
            break;
          }
        }
      }

      // Check if non-root user was set at all
      if (!hasUserDirective) {
        findingIndex++;
        findings.push({
          id: `DOCK-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.HIGH,
          title: 'Missing Non-Root USER Directive',
          description:
            'Dockerfile içerisinde `USER` direktifi tanımlanmamış. Varsayılan olarak konteyner root yetkileriyle çalışacaktır.',
          file: dfile.relativePath,
          recommendation: 'İmaj çalıştırmadan önce `USER node` veya `USER 10001` gibi kısıtlı kullanıcıya geçiş yapın.',
          owasp: 'A05:2021',
        });
      }
    }

    // 3. Audit docker-compose.yml files
    const composeFiles = context.files.filter(
      (f) =>
        f.relativePath === 'docker-compose.yml' ||
        f.relativePath === 'docker-compose.yaml'
    );

    for (const cfile of composeFiles) {
      const content = readFileContent(cfile.path);
      if (content.includes('privileged: true')) {
        findingIndex++;
        findings.push({
          id: `DOCK-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.CRITICAL,
          title: 'Privileged Mode in Docker Compose',
          description: 'docker-compose dosyasında `privileged: true` ayarı tespit edildi. Bu ayar host sisteminde container kaçışına (escape) olanak tanır.',
          file: cfile.relativePath,
          recommendation: 'Privileged modunu kaldırın, yalnızca ihtiyaç duyulan Linux yeteneklerini (`cap_add`) verin.',
          owasp: 'A05:2021',
        });
      }
    }

    return findings;
  }
}
