/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Disclaimer Generator
 *
 * Generates legal disclaimers and metadata for mcp-verify reports.
 * These disclaimers clarify the scope and limitations of the security analysis.
 */

import type {
  ReportDisclaimer,
  ReportMetadata,
} from "../mcp-server/entities/validation.types";
import { translations, Language } from "./i18n";

// Tool version - should match package.json
const TOOL_VERSION = "1.0.0";

export interface DisclaimerOptions {
  /** Language for disclaimer text */
  language?: Language;
  /** Whether LLM analysis was used */
  llmUsed?: boolean;
  /** LLM provider if used */
  llmProvider?: "anthropic" | "openai" | "ollama";
  /** Which modules were executed */
  modulesExecuted?: Array<"security" | "quality" | "fuzzing" | "protocol">;
}

/**
 * Generate report metadata
 */
export function generateMetadata(
  options: DisclaimerOptions = {},
): ReportMetadata {
  return {
    toolVersion: TOOL_VERSION,
    modulesExecuted: options.modulesExecuted ?? ["security", "quality"],
    llmUsed: options.llmUsed ?? false,
    llmProvider: options.llmProvider,
  };
}

/**
 * Generate report disclaimer with translations
 */
export function generateDisclaimer(
  options: DisclaimerOptions = {},
): ReportDisclaimer {
  const lang = options.language ?? "en";
  const t = translations[lang];

  const disclaimer: ReportDisclaimer = {
    text: t.disclaimer_main_text,
    scope: [
      t.disclaimer_scope_1,
      t.disclaimer_scope_2,
      t.disclaimer_scope_3,
      t.disclaimer_scope_4,
    ],
    limitations: [
      t.disclaimer_limitations_1,
      t.disclaimer_limitations_2,
      t.disclaimer_limitations_3,
      t.disclaimer_limitations_4,
      t.disclaimer_limitations_5,
    ],
  };

  // Add LLM notice if applicable
  if (options.llmUsed && options.llmProvider) {
    disclaimer.llmNotice = (
      t.disclaimer_llm_notice || "Analysis powered by {provider}"
    ).replace("{provider}", options.llmProvider);
  }

  return disclaimer;
}

/**
 * Generate full disclaimer text for CLI output
 */
export function getDisclaimerText(options: DisclaimerOptions = {}): string {
  const lang = options.language ?? "en";
  const t = translations[lang];

  const lines: string[] = [
    "",
    `━━━ ${t.disclaimer_title} ━━━`,
    "",
    t.disclaimer_main_text,
    "",
    t.disclaimer_scope_title,
    `  • ${t.disclaimer_scope_1}`,
    `  • ${t.disclaimer_scope_2}`,
    `  • ${t.disclaimer_scope_3}`,
    `  • ${t.disclaimer_scope_4}`,
    "",
    t.disclaimer_limitations_title,
    `  • ${t.disclaimer_limitations_1}`,
    `  • ${t.disclaimer_limitations_2}`,
    `  • ${t.disclaimer_limitations_3}`,
    `  • ${t.disclaimer_limitations_4}`,
    `  • ${t.disclaimer_limitations_5}`,
    "",
  ];

  if (options.llmUsed && options.llmProvider) {
    lines.push(
      (t.disclaimer_llm_notice || "Analysis powered by {provider}").replace(
        "{provider}",
        options.llmProvider,
      ),
    );
    lines.push("");
  }

  lines.push(t.disclaimer_professional_audit);
  lines.push("");

  return lines.join("\n");
}

/**
 * Get short disclaimer for inline display
 */
export function getShortDisclaimer(language: Language = "en"): string {
  const t = translations[language];
  return t.disclaimer_no_warranty;
}

/**
 * Get LLM data sharing notice
 */
export function getLlmNotice(
  provider: string,
  language: Language = "en",
): string {
  const t = translations[language];
  return (t.disclaimer_llm_notice || "Analysis powered by {provider}").replace(
    "{provider}",
    provider,
  );
}
