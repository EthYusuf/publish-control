// ═══════════════════════════════════════════════════════════════
// Publish Control — File Walker Utility
// ═══════════════════════════════════════════════════════════════

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { FileInfo } from '../core/types.js';

/** Directories to always skip when walking the file tree */
const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.cache',
  '__pycache__',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  'vendor',
  '.idea',
  '.vscode',
  '.vs',
]);

/** File extensions to scan */
const SCANNABLE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.json', '.yaml', '.yml',
  '.env', '.ini', '.cfg', '.conf',
  '.toml',
  '.py', '.go', '.java', '.rb', '.php',
  '.html', '.htm', '.xml',
  '.sh', '.bash', '.zsh', '.ps1',
  '.sql',
  '.md',
]);

/** Special filenames to always include regardless of extension */
const SPECIAL_FILES = new Set([
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.gitignore',
  '.dockerignore',
  '.npmignore',
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.staging',
  '.env.test',
  '.env.example',
  'Makefile',
  'Procfile',
]);

/**
 * Recursively walk a directory and collect FileInfo entries for scannable files.
 *
 * @param rootPath - Absolute path to the project root
 * @param maxFiles - Maximum number of files to collect (default: 5000)
 * @returns Array of FileInfo objects
 */
export function walkDirectory(rootPath: string, maxFiles = 5000): FileInfo[] {
  const results: FileInfo[] = [];

  function walk(dir: string): void {
    if (results.length >= maxFiles) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      // Permission denied or other access errors – skip silently
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) return;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(fullPath);
        }
        // Also walk dot-directories that are special (like .github)
        if (entry.name === '.github' || entry.name === '.docker') {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const isSpecial = SPECIAL_FILES.has(entry.name);
        const isScannable = SCANNABLE_EXTENSIONS.has(ext);

        if (isSpecial || isScannable) {
          try {
            const stat = fs.statSync(fullPath);
            // Skip very large files (> 1MB) to avoid memory issues
            if (stat.size <= 1_048_576) {
              results.push({
                path: fullPath,
                relativePath: path.relative(rootPath, fullPath).replace(/\\/g, '/'),
                extension: ext,
                size: stat.size,
              });
            }
          } catch {
            // Skip files we can't stat
          }
        }
      }
    }
  }

  walk(rootPath);
  return results;
}

/**
 * Read the content of a file, returning an empty string on error.
 */
export function readFileContent(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return '';
  }
}

/**
 * Check if a file or directory exists.
 */
export function fileExists(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}
