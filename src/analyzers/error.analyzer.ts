// ═══════════════════════════════════════════════════════════════
// Publish Control — Error Handling Analyzer
// Detects stack trace exposure and information leakage in errors.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { ERROR_HANDLING_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class ErrorHandlingAnalyzer extends BaseAnalyzer {
  readonly name = 'error';
  readonly displayName = 'Error Handling & Info Disclosure';
  readonly emoji = '❌';

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

        for (const pattern of ERROR_HANDLING_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `ERR-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.MEDIUM,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                'Hata ayrıntılarını istemciye doğrudan göndermeyin. Sunucu tarafında loglayın ve istemciye genel bir hata kodu/mesajı (ör. "Internal Server Error") dönün.',
              owasp: 'A05:2021 - Security Misconfiguration',
              cwe: 'CWE-209: Generation of Error Message Containing Sensitive Information',
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}
