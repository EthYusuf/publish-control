// ═══════════════════════════════════════════════════════════════
// Publish Control — Project Scanner
// Scans the project directory and builds a ProjectContext.
// ═══════════════════════════════════════════════════════════════

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ProjectContext } from './types.js';
import { walkDirectory, readFileContent, fileExists } from '../utils/file-walker.js';

/**
 * Scan a project directory and build a comprehensive ProjectContext.
 */
export function scanProject(rootPath: string): ProjectContext {
  const absRoot = path.resolve(rootPath);

  if (!fs.existsSync(absRoot)) {
    throw new Error(`Project path does not exist: ${absRoot}`);
  }

  if (!fs.statSync(absRoot).isDirectory()) {
    throw new Error(`Project path is not a directory: ${absRoot}`);
  }

  // Collect files
  const files = walkDirectory(absRoot);

  // Parse package.json if present
  let packageJson: Record<string, unknown> | undefined;
  const pkgPath = path.join(absRoot, 'package.json');
  if (fileExists(pkgPath)) {
    try {
      packageJson = JSON.parse(readFileContent(pkgPath));
    } catch {
      // Malformed package.json — leave undefined
    }
  }

  // Detect Docker
  const hasDocker =
    fileExists(path.join(absRoot, 'Dockerfile')) ||
    fileExists(path.join(absRoot, 'docker-compose.yml')) ||
    fileExists(path.join(absRoot, 'docker-compose.yaml'));

  // Detect .env files
  const hasEnvFile = files.some(f =>
    f.relativePath === '.env' ||
    f.relativePath.startsWith('.env.') ||
    f.relativePath.endsWith('.env')
  );

  // Detect TypeScript config
  const hasTsConfig = fileExists(path.join(absRoot, 'tsconfig.json'));

  // Detect framework
  const framework = detectFramework(packageJson);

  // Detect language
  const language = detectLanguage(files, hasTsConfig);

  // Read .gitignore
  const gitignorePath = path.join(absRoot, '.gitignore');
  const hasGitignore = fileExists(gitignorePath);
  const gitignorePatterns = hasGitignore
    ? readFileContent(gitignorePath)
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
    : [];

  return {
    rootPath: absRoot,
    files,
    packageJson,
    hasDocker,
    hasEnvFile,
    hasTsConfig,
    framework,
    language,
    hasGitignore,
    gitignorePatterns,
  };
}

/**
 * Detect the web framework used in the project.
 */
function detectFramework(packageJson?: Record<string, unknown>): string | undefined {
  if (!packageJson) return undefined;

  const allDeps = {
    ...(packageJson.dependencies as Record<string, string> || {}),
    ...(packageJson.devDependencies as Record<string, string> || {}),
  };

  if ('next' in allDeps) return 'nextjs';
  if ('@nestjs/core' in allDeps) return 'nestjs';
  if ('nuxt' in allDeps || 'nuxt3' in allDeps) return 'nuxt';
  if ('fastify' in allDeps) return 'fastify';
  if ('koa' in allDeps) return 'koa';
  if ('hapi' in allDeps || '@hapi/hapi' in allDeps) return 'hapi';
  if ('express' in allDeps) return 'express';
  if ('django' in allDeps) return 'django';
  if ('flask' in allDeps) return 'flask';
  if ('react' in allDeps) return 'react';
  if ('vue' in allDeps) return 'vue';
  if ('angular' in allDeps || '@angular/core' in allDeps) return 'angular';

  return undefined;
}

/**
 * Detect the primary programming language.
 */
function detectLanguage(
  files: { extension: string }[],
  hasTsConfig: boolean,
): 'typescript' | 'javascript' | 'mixed' | 'unknown' {
  let tsCount = 0;
  let jsCount = 0;

  for (const f of files) {
    if (f.extension === '.ts' || f.extension === '.tsx') tsCount++;
    if (f.extension === '.js' || f.extension === '.jsx' || f.extension === '.mjs' || f.extension === '.cjs') jsCount++;
  }

  if (tsCount > 0 && jsCount > 0) return 'mixed';
  if (tsCount > 0 || hasTsConfig) return 'typescript';
  if (jsCount > 0) return 'javascript';
  return 'unknown';
}
