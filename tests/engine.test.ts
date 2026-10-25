// ═══════════════════════════════════════════════════════════════
// Publish Control — Analysis Engine Unit Tests
// ═══════════════════════════════════════════════════════════════

import { describe, it, expect } from 'vitest';
import { AnalysisEngine } from '../src/core/engine.js';
import * as path from 'node:path';

describe('AnalysisEngine', () => {
  it('should instantiate and analyze the publish-control project itself', async () => {
    const engine = new AnalysisEngine();
    const projectRoot = path.resolve('.');

    const report = await engine.analyze(projectRoot, {
      severity: 'all',
    });

    expect(report).toBeDefined();
    expect(report.results.length).toBe(17); // All 17 analyzers executed
    expect(report.overallScore).toBeGreaterThanOrEqual(0);
    expect(report.overallScore).toBeLessThanOrEqual(100);
  });
});
