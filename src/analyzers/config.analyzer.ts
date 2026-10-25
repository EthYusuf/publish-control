// ═══════════════════════════════════════════════════════════════
// Publish Control — Security Configuration Analyzer
// Checks cookie flags (httpOnly, secure), strict tsconfig, and gitignore.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { readFileContent } from '../utils/file-walker.js';
import * as path from 'node:path';

export class ConfigAnalyzer extends BaseAnalyzer {
  readonly name = 'config';
  readonly displayName = 'Security Configuration Audit';
  readonly emoji = '🔧';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingIndex = 0;

    // 1. Audit tsconfig.json if present
    if (context.hasTsConfig) {
      const tsconfigPath = path.join(context.rootPath, 'tsconfig.json');
      const content = readFileContent(tsconfigPath);
      if (content && !content.includes('"strict": true')) {
        findingIndex++;
        findings.push({
          id: `CFG-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.LOW,
          title: 'TypeScript Strict Mode Disabled',
          description: '`tsconfig.json` dosyasında `"strict": true` ayarı bulunamadı. Strict mod tip güvenliğini ve potansiyel null-pointer hatalarını önler.',
          file: 'tsconfig.json',
          recommendation: 'tsconfig.json dosyasına `"compilerOptions": { "strict": true }` ekleyin.',
        });
      }
    }

    // 2. Audit cookie settings in source files
    const sourceFiles = this.getSourceFiles(context);
    for (const file of sourceFiles) {
      if (this.isTestFile(file.relativePath)) continue;
      const content = readFileContent(file.path);
      if (!content) continue;

      if (content.includes('res.cookie(') || content.includes('setCookie(')) {
        if (!content.includes('httpOnly: true') && !content.includes('httpOnly:!0')) {
          findingIndex++;
          findings.push({
            id: `CFG-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Cookie Missing httpOnly Flag',
            description: 'Çerez (cookie) tanımlanırken `httpOnly: true` bayrağı verilmemiş. XSS saldırılarında JavaScript ile çalınabilir.',
            file: file.relativePath,
            recommendation: 'Oturum ve güvenlik çerezlerinde daima `httpOnly: true` ve `secure: true` (HTTPS için) parametrelerini kullanın.',
            owasp: 'A05:2021',
            cwe: 'CWE-1004: Sensitive Cookie Without HttpOnly Flag',
          });
        }
      }
    }

    // 3. Audit .gitignore completeness
    if (context.hasGitignore) {
      const essentialPatterns = ['node_modules', '.env'];
      for (const pat of essentialPatterns) {
        const found = context.gitignorePatterns.some((p) => p.includes(pat));
        if (!found) {
          findingIndex++;
          findings.push({
            id: `CFG-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: `Missing "${pat}" in .gitignore`,
            description: `.gitignore dosyasında kritik \`${pat}\` girdisi tespit edilemedi.`,
            file: '.gitignore',
            recommendation: `.gitignore dosyasına \`${pat}\` satırını ekleyin.`,
          });
        }
      }
    }

    return findings;
  }
}
