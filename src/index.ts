#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// Publish Control — MCP Server Entry Point
// AI-assisted code security analysis MCP server.
// ═══════════════════════════════════════════════════════════════

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('🛡️ Publish Control MCP Server running on stdio');
}

main().catch((error: unknown) => {
  console.error('Fatal error starting Publish Control:', error);
  process.exit(1);
});
