// ═══════════════════════════════════════════════════════════════
// Publish Control — MCP Server Setup
// Defines the MCP server tools for security analysis.
// ═══════════════════════════════════════════════════════════════

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AnalysisEngine } from './core/engine.js';
import { Reporter } from './core/reporter.js';

/**
 * Create and configure the Publish Control MCP server.
 */
export function createServer(): McpServer {
  const server = new McpServer({
    name: 'publish-control',
    version: '1.0.0',
  });

  const engine = new AnalysisEngine();

  // ═══════════════════════════════════════════════════════════
  // TOOL 1: publish_control — Full Security Analysis
  // ═══════════════════════════════════════════════════════════
  server.tool(
    'publish_control',
    `Projedeki tüm kodları 17 farklı güvenlik kategorisinde analiz eder.
Hardcoded secrets, env güvenliği, server açıkları, SQL/NoSQL injection,
authentication, dependency güvenliği, Docker, CORS, SSRF, path traversal,
HTTPS/TLS, rate limiting, dosya izinleri, error handling, logging,
güvenlik konfigürasyonu ve kod kalitesi kontrolleri yapar.
Yayına almadan önce kapsamlı güvenlik raporu üretir.`,
    {
      projectPath: z.string().describe('Taranacak projenin kök dizini (absolute path)'),
      categories: z.array(z.string()).optional().describe(
        'Sadece belirli kategorileri çalıştır. Mevcut: secrets, env, injection, auth, server, cors, https, path, ssrf, docker, deps, rate-limit, permissions, error, logging, config, quality'
      ),
      severity: z.enum(['all', 'critical', 'high', 'medium']).default('all').describe(
        'Minimum severity filtresi'
      ),
    },
    async ({ projectPath, categories, severity }) => {
      try {
        const report = await engine.analyze(projectPath, { categories, severity });
        const markdown = Reporter.toMarkdown(report);

        return {
          content: [{ type: 'text' as const, text: markdown }],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text' as const, text: `❌ Analiz hatası: ${message}` }],
          isError: true,
        };
      }
    },
  );

  // ═══════════════════════════════════════════════════════════
  // TOOL 2: publish_control_quick — Quick Scan
  // ═══════════════════════════════════════════════════════════
  server.tool(
    'publish_control_quick',
    `Sadece CRITICAL ve HIGH seviye kontrolleri çalıştırır.
Secrets, env exposure, injection ve auth gibi en kritik kontrolleri yapar.
Hızlı güvenlik değerlendirmesi için kullanılır.`,
    {
      projectPath: z.string().describe('Taranacak projenin kök dizini'),
    },
    async ({ projectPath }) => {
      try {
        const report = await engine.analyze(projectPath, {
          severity: 'high',
          categories: ['secrets', 'env', 'injection', 'auth', 'server'],
        });
        const markdown = Reporter.toMarkdown(report);

        return {
          content: [{ type: 'text' as const, text: markdown }],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text' as const, text: `❌ Hızlı tarama hatası: ${message}` }],
          isError: true,
        };
      }
    },
  );

  // ═══════════════════════════════════════════════════════════
  // TOOL 3: publish_control_fix — Fix Suggestions
  // ═══════════════════════════════════════════════════════════
  server.tool(
    'publish_control_fix',
    `Belirli bir güvenlik bulgusu için detaylı düzeltme önerileri ve
kod örnekleri üretir. Önce publish_control ile tarama yapın,
ardından bulgu ID'si ile düzeltme önerisi alın.`,
    {
      findingId: z.string().describe("Düzeltilecek bulgunun ID'si (ör: SEC-001)"),
      projectPath: z.string().describe('Proje kök dizini'),
    },
    async ({ findingId, projectPath }) => {
      try {
        const fix = await engine.suggestFix(findingId, projectPath);

        return {
          content: [{ type: 'text' as const, text: fix }],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text' as const, text: `❌ Düzeltme önerisi hatası: ${message}` }],
          isError: true,
        };
      }
    },
  );

  return server;
}
