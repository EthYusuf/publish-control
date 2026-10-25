// ═══════════════════════════════════════════════════════════════
// Publish Control — Dependency Vulnerability Analyzer
// Audits package.json for wildcard versions, lockfiles, and known bad packages.
// ═══════════════════════════════════════════════════════════════

import { BaseAnalyzer } from './base-analyzer.js';
import { Severity } from '../core/types.js';
import type { Finding, ProjectContext } from '../core/types.js';
import { fileExists } from '../utils/file-walker.js';
import * as path from 'node:path';

/** High-risk or deprecation/malware-tainted packages list */
const SUSPICIOUS_OR_DEPRECATED_PACKAGES: Record<string, string> = {
  request: '`request` kütüphanesi yıllar önce kullanımdan kalktı (deprecated) ve güvenlik yamaları almıyor. `fetch` veya `axios` kullanın.',
  'node-uuid': '`node-uuid` paketi artık güncellenmiyor. Yerine `uuid` kullanın.',
  nomnom: '`nomnom` paketi terk edildi. Modern alternatifler (`commander`, `yargs`) tercih edin.',
  'crypto-js': 'Kullanımı karmaşık ve modern Web Crypto / native `node:crypto` API varken tavsiye edilmez.',
};

export class DepsAnalyzer extends BaseAnalyzer {
  readonly name = 'deps';
  readonly displayName = 'Dependency Vulnerability Audit';
  readonly emoji = '📦';

  async analyze(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingIndex = 0;

    if (!context.packageJson) {
      return findings;
    }

    // 1. Check if package-lock.json / yarn.lock / pnpm-lock.yaml exists
    const hasLockfile =
      fileExists(path.join(context.rootPath, 'package-lock.json')) ||
      fileExists(path.join(context.rootPath, 'yarn.lock')) ||
      fileExists(path.join(context.rootPath, 'pnpm-lock.yaml')) ||
      fileExists(path.join(context.rootPath, 'bun.lockb'));

    if (!hasLockfile) {
      findingIndex++;
      findings.push({
        id: `DEP-${String(findingIndex).padStart(3, '0')}`,
        analyzer: this.name,
        severity: Severity.HIGH,
        title: 'Missing Package Lockfile',
        description: 'Projede `package-lock.json` veya alternatif lock dosyası bulunamadı. Bu durum tedarik zinciri saldırılarına ve kararsız buildlere yol açabilir.',
        file: 'package.json',
        recommendation: '`npm install` çalıştırarak bir `package-lock.json` oluşturun ve versiyon kontrol sistemine ekleyin.',
        owasp: 'A06:2021 - Vulnerable and Outdated Components',
      });
    }

    // 2. Check for wildcard / loose dependency versions
    const deps = (context.packageJson.dependencies as Record<string, string>) || {};
    const devDeps = (context.packageJson.devDependencies as Record<string, string>) || {};
    const all = { ...deps, ...devDeps };

    for (const [pkg, ver] of Object.entries(all)) {
      if (ver === '*' || ver === 'latest') {
        findingIndex++;
        findings.push({
          id: `DEP-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.HIGH,
          title: `Wildcard/Latest Version for "${pkg}"`,
          description: `\`${pkg}\` için \`${ver}\` versiyonu tanımlanmış. Her derlemede farklı kod çekilmesi supply-chain riskini artırır.`,
          file: 'package.json',
          recommendation: `Spesifik semver versiyon kısıtlamaları (ör. \`^1.2.3\` veya sabit \`1.2.3\`) belirtin.`,
          owasp: 'A06:2021',
        });
      }

      if (SUSPICIOUS_OR_DEPRECATED_PACKAGES[pkg]) {
        findingIndex++;
        findings.push({
          id: `DEP-${String(findingIndex).padStart(3, '0')}`,
          analyzer: this.name,
          severity: Severity.MEDIUM,
          title: `Deprecated/Insecure Dependency: ${pkg}`,
          description: SUSPICIOUS_OR_DEPRECATED_PACKAGES[pkg],
          file: 'package.json',
          recommendation: `\`${pkg}\` paketini modern ve güvenli bir alternatifle değiştirin.`,
          owasp: 'A06:2021',
        });
      }
    }

    return findings;
  }
}
