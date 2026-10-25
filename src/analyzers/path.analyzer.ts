// ═══════════════════════════════════════════════════════════════
// Publish Control — Path Traversal Analyzer
// Detects directory traversal vulnerabilities in file handling.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { PATH_TRAVERSAL_PATTERNS } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class PathTraversalAnalyzer extends BaseAnalyzer {
  readonly name = 'path';
  readonly displayName = 'Path Traversal Detection';
  readonly emoji = '📂';

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

        for (const pattern of PATH_TRAVERSAL_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `PTH-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.CRITICAL,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                'Dosya yollarını oluştururken `path.resolve` sonrasında hedefin güvenli bir kök dizin içinde kaldığını `resolvedPath.startsWith(SAFE_DIR)` ile denetleyin veya girdiyi `path.basename()` ile sınırlayın.',
              owasp: 'A01:2021 - Broken Access Control',
              cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}
