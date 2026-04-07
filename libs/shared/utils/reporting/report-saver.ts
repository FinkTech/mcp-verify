/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Report Saver Utility
 *
 * Shared helper for saving validation reports to files.
 * Used by both CLI commands and MCP Server tools to ensure consistency.
 */

import fs from "fs";
import path from "path";
import type { Report } from "../../../../libs/core/domain/mcp-server/entities/validation.types";
import { HtmlReportGenerator } from "../../../../libs/core/domain/reporting/html-generator";
import { MarkdownReportGenerator } from "../../../../libs/core/domain/reporting/markdown-generator";
import { SarifGenerator } from "../../../../libs/core/domain/reporting/sarif-generator";
import type { Language } from "../../../../libs/core/domain/reporting/i18n";

export interface SaveReportOptions {
  outputDir?: string;
  formats?: Array<"json" | "markdown" | "html" | "sarif">;
  lang?: Language;
  serverName?: string;
}

export interface SavedReportPaths {
  json?: string;
  markdown?: string;
  html?: string;
  sarif?: string;
}

/**
 * Saves validation report to files in organized subdirectories
 *
 * @param report - The validation report to save
 * @param options - Options for output directory, formats, and language
 * @returns Object with paths to saved files
 */
export async function saveReportsToFiles(
  report: Report,
  options: SaveReportOptions = {},
): Promise<SavedReportPaths> {
  const {
    outputDir = "./reportes",
    formats = ["json", "markdown", "html"],
    lang = "en",
    serverName,
  } = options;

  // Generate timestamp and filename base
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeName = (serverName || report.server_name || "mcp-server").replace(
    /[^a-zA-Z0-9]/g,
    "-",
  );
  const filenameBase = `${safeName}-${timestamp}`;

  const savedPaths: SavedReportPaths = {};

  // Save JSON
  if (formats.includes("json")) {
    const jsonDir = path.join(outputDir, "json");
    fs.mkdirSync(jsonDir, { recursive: true });
    const jsonPath = path.join(jsonDir, `${filenameBase}.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    savedPaths.json = jsonPath;
  }

  // Save Markdown
  if (formats.includes("markdown")) {
    const mdDir = path.join(outputDir, "md");
    fs.mkdirSync(mdDir, { recursive: true });
    const mdContent = MarkdownReportGenerator.generate(report, lang);
    const mdPath = path.join(mdDir, `${filenameBase}.md`);
    fs.writeFileSync(mdPath, mdContent, "utf-8");
    savedPaths.markdown = mdPath;
  }

  // Save HTML
  if (formats.includes("html")) {
    const htmlDir = path.join(outputDir, "html");
    fs.mkdirSync(htmlDir, { recursive: true });
    const htmlContent = HtmlReportGenerator.generate(report, lang);
    const htmlPath = path.join(htmlDir, `${filenameBase}.html`);
    fs.writeFileSync(htmlPath, htmlContent, "utf-8");
    savedPaths.html = htmlPath;
  }

  // Save SARIF
  if (formats.includes("sarif")) {
    const sarifDir = path.join(outputDir, "sarif");
    fs.mkdirSync(sarifDir, { recursive: true });
    const sarifContent = SarifGenerator.generate(report);
    const sarifPath = path.join(sarifDir, `${filenameBase}.sarif`);
    fs.writeFileSync(sarifPath, sarifContent, "utf-8");
    savedPaths.sarif = sarifPath;
  }

  return savedPaths;
}
