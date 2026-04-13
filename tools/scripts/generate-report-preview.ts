#!/usr/bin/env node
/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Generates a fixed preview HTML report with mock data.
 * Run: npm run preview:report
 * Output: reportes/html/preview.html
 *
 * Open reportes/html/preview.html in a browser to review report design
 * without running a full validation.
 */

import fs from "fs";
import path from "path";
import { HtmlReportGenerator } from "../../libs/core/domain/reporting/html-generator";
import type { Report } from "../../libs/core/domain/mcp-server/entities/validation.types";

const ROOT = path.resolve(__dirname, "../..");

const MOCK_REPORT: Report = {
  server_name: "demo-mcp-server",
  url: "http://localhost:3000",
  status: "valid",
  protocol_version: "2024-11-05",

  security: {
    score: 78,
    level: "Medium Risk",
    findings: [
      {
        severity: "high",
        message: "Tool accepts unrestricted file paths",
        component: "read_file",
        ruleCode: "MCP-SEC-001",
        remediation: "Validate and sanitize input paths",
      },
      {
        severity: "medium",
        message: "Missing rate limiting on tool invocations",
        component: "general",
        ruleCode: "MCP-SEC-002",
        remediation: "Implement throttling per client",
      },
      {
        severity: "low",
        message: "Tool description could be more detailed",
        component: "list_files",
        ruleCode: "MCP-QUAL-001",
        remediation: "Add parameter documentation",
      },
    ],
    criticalCount: 0,
    highCount: 1,
    mediumCount: 1,
    lowCount: 1,
  },

  quality: {
    score: 85,
    issues: [
      {
        severity: "medium",
        message: "Inconsistent naming convention",
        component: "tools",
        suggestion: "Use snake_case for tool names",
      },
    ],
  },

  protocolCompliance: {
    passed: true,
    score: 100,
    issues: [],
    testsPassed: 12,
    testsFailed: 0,
    totalTests: 12,
  },

  tools: {
    count: 3,
    valid: 2,
    invalid: 1,
    items: [
      {
        name: "read_file",
        description: "Reads file contents from the filesystem",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
        status: "valid",
      },
      {
        name: "list_files",
        description: "Lists files in a directory",
        inputSchema: {
          type: "object",
          properties: { directory: { type: "string" } },
        },
        status: "valid",
      },
      {
        name: "execute_command",
        description: "Executes a shell command",
        inputSchema: { type: "object", properties: {} },
        status: "invalid",
      },
    ],
  },

  resources: {
    count: 2,
    valid: 2,
    invalid: 0,
    items: [
      {
        name: "file:///docs",
        description: "Documentation",
        uri: "file:///docs",
        mimeType: "text/markdown",
        status: "valid" as const,
      },
      {
        name: "config",
        description: "Server config",
        uri: "file:///config.json",
        mimeType: "application/json",
        status: "valid" as const,
      },
    ],
  },

  prompts: {
    count: 1,
    valid: 1,
    invalid: 0,
    items: [
      {
        name: "summarize",
        description: "Summarize content",
        arguments: [{ name: "content", required: true }],
        status: "valid" as const,
      },
    ],
  },

  timestamp: new Date().toISOString(),
  duration_ms: 1234,

  badges: {
    markdown: "[![MCP Valid](https://img.shields.io/badge/MCP-Valid-green)]()",
    html: '<img src="https://img.shields.io/badge/MCP-Valid-green" alt="MCP Valid"/>',
    url: "https://example.com/badge",
  },
};

function main() {
  const outputDir = path.join(ROOT, "reports", "preview");
  const outputPath = path.join(outputDir, "html-preview.html");

  fs.mkdirSync(outputDir, { recursive: true });

  const html = HtmlReportGenerator.generate(MOCK_REPORT, "en");
  fs.writeFileSync(outputPath, html, "utf-8");

  console.log(`Preview report generated: ${outputPath}`);
  console.log("Open in browser to review design changes.");
}

main();
