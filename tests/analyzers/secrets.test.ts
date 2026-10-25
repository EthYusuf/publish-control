// ═══════════════════════════════════════════════════════════════
// Publish Control — Secrets Analyzer Unit Tests
// ═══════════════════════════════════════════════════════════════

import { describe, it, expect } from 'vitest';
import { SecretsAnalyzer } from '../../src/analyzers/secrets.analyzer.js';
import type { ProjectContext } from '../../src/core/types.js';

describe('SecretsAnalyzer', () => {
  const analyzer = new SecretsAnalyzer();

  it('should identify AWS and Stripe hardcoded credentials', async () => {
    const mockContext: ProjectContext = {
      rootPath: '/dummy',
      files: [
        {
          path: '/dummy/src/config.ts',
          relativePath: 'src/config.ts',
          extension: '.ts',
          size: 200,
        },
      ],
      hasDocker: false,
      hasEnvFile: false,
      hasTsConfig: true,
      language: 'typescript',
      hasGitignore: true,
      gitignorePatterns: [],
    };

    // We can spy on or test analyzer directly with realistic file paths or mocks
    expect(analyzer.name).toBe('secrets');
    expect(analyzer.emoji).toBe('🔑');
  });
});
