// ═══════════════════════════════════════════════════════════════
// Publish Control — Permissions Analyzer
// Audits file permissions, upload validation, and overly permissive modes.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { readFileContent } from '../utils/file-walker.js';

export class PermissionsAnalyzer extends BaseAnalyzer {
  readonly name = 'permissions';
  readonly displayName = 'File Permissions & Upload Audit';
  readonly emoji = '🗂️';

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

        // Check for chmod 777 or 0o777
        if (trimmed.match(/chmod(?:Sync)?\s*\([^,]+,\s*(?:0o?777|777|['"]777['"])/)) {
          findingIndex++;
          findings.push({
            id: `PERM-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'World-Writable Permissions (0777)',
            description: 'Dosya veya dizine herkesin yazabileceği (0777) izin atanıyor.',
            file: file.relativePath,
            line: i + 1,
            code: this.redactLine(trimmed),
            recommendation:
              'En az yetki ilkesine (least privilege) uygun olarak dosyalar için 0644 veya 0600, dizinler için 0755 kullanın.',
            cwe: 'CWE-732: Incorrect Permission Assignment for Critical Resource',
          });
        }

        // Check for multer/upload without fileFilter / limit
        if (
          trimmed.includes('multer(') &&
          !content.includes('fileFilter') &&
          !content.includes('limits')
        ) {
          findingIndex++;
          findings.push({
            id: `PERM-${String(findingIndex).padStart(3, '0')}`,
            analyzer: this.name,
            severity: Severity.HIGH,
            title: 'Unrestricted File Upload Configuration',
            description: '`multer` yapılandırmasında dosya türü filtresi (`fileFilter`) veya boyut kısıtlaması (`limits`) tanımlanmamış.',
            file: file.relativePath,
            line: i + 1,
            recommendation:
              'Yüklenen dosyaların uzantılarını, MIME türlerini ve boyut sınırını (`limits: { fileSize: 5 * 1024 * 1024 }`) kesin olarak sınırlandırın.',
            owasp: 'A04:2021 - Insecure Design',
            cwe: 'CWE-434: Unrestricted Upload of File with Dangerous Type',
          });
          break; // once per file
        }
      }
    }

    return findings;
  }
}
