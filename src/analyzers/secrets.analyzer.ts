// ═══════════════════════════════════════════════════════════════
// Publish Control — Secrets Analyzer
// Detects hardcoded API keys, tokens, passwords, and high-entropy secrets.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { SECRET_PATTERNS, calculateEntropy } from '../utils/patterns.js';
import { readFileContent } from '../utils/file-walker.js';

export class SecretsAnalyzer extends BaseAnalyzer {
  readonly name = 'secrets';
  readonly displayName = 'Hardcoded Secrets Detection';
  readonly emoji = '🔑';

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

        // Check against known secret patterns
        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(line)) {
            findingIndex++;
            findings.push({
              id: `SEC-${String(findingIndex).padStart(3, '0')}`,
              analyzer: this.name,
              severity: Severity.CRITICAL,
              title: pattern.name,
              description: pattern.description,
              file: file.relativePath,
              line: i + 1,
              code: this.redactLine(trimmed),
              recommendation:
                'API anahtarını veya gizli bilgiyi koddan kaldırın. Ortam değişkeni (process.env) veya güvenli bir secret manager (AWS Secrets Manager, Vault vb.) kullanın.',
              owasp: 'A07:2021 - Identification and Authentication Failures',
              cwe: 'CWE-798: Use of Hard-coded Credentials',
            });
            break; // One finding per line to avoid duplication
          }
        }

        // Shannon entropy check for potential undisclosed secrets/tokens
        const tokenMatch = trimmed.match(/(?:['"`])([A-Za-z0-9+/=_-]{28,})(?:['"`])/);
        if (tokenMatch && tokenMatch[1]) {
          const candidate = tokenMatch[1];
          // Skip long URLs or import paths
          if (!candidate.includes('/') && !candidate.includes('.')) {
            const entropy = calculateEntropy(candidate);
            if (entropy > 4.5) {
              findingIndex++;
              findings.push({
                id: `SEC-${String(findingIndex).padStart(3, '0')}`,
                analyzer: this.name,
                severity: Severity.HIGH,
                title: 'High Entropy String (Potential Secret)',
                description: `Yüksek entropili (${entropy.toFixed(2)}) gizli anahtar veya şifreli token şüphesi.`,
                file: file.relativePath,
                line: i + 1,
                code: this.redactLine(trimmed),
                recommendation:
                  'Bu rastgele karakter dizesinin hassas bir veri veya API anahtarı olup olmadığını denetleyin ve ortam değişkenine taşıyın.',
                owasp: 'A07:2021',
                cwe: 'CWE-798',
              });
            }
          }
        }
      }
    }

    return findings;
  }
}
