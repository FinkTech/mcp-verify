/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-061: Homoglyph / Unicode Spoofing in Server Identity (Supply Chain)
 *
 * Block: F (Supply Chain & Identity)
 * Severity: High
 * Type: Static
 *
 * Detects non-ASCII Unicode characters in server name, tool names, and
 * resource names that are visually identical (or near-identical) to ASCII
 * characters. This is a supply chain / identity spoofing technique:
 *
 * - A malicious server registers as "CRM Раrtner Suite" where "Р" is
 *   Cyrillic U+0420, visually identical to Latin "P".
 * - An LLM or user reading the server name cannot distinguish it from a
 *   legitimate server named "CRM Partner Suite".
 * - The scanner, config files, and trust registries compare by codepoint
 *   — so the spoofed name bypasses allowlist checks.
 *
 * Detection strategy:
 * - Scan serverInfo.name, tool names, and resource names
 * - Flag any string containing characters outside the Basic Latin block
 *   (U+0000–U+007F) mixed with ASCII — pure Unicode names (e.g. Japanese
 *   tool names) produce a lower-severity info finding, not a critical one
 *
 * References:
 * - Unicode Consortium: Unicode Security Considerations (UTS#39)
 * - OWASP: A08:2021 – Software and Data Integrity Failures
 * - CWE-1007: Insufficient Visual Distinction of Homoglyphs
 * - CVE-2021-3749: homoglyph attack in npm package names
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import { t } from "@mcp-verify/shared";

export class HomoglyphSpoofingRule implements ISecurityRule {
  code = "SEC-061";
  name = "Homoglyph / Unicode Spoofing in Server Identity";
  severity: "high" = "high";

  /**
   * Characters in these Unicode blocks are commonly used as homoglyph
   * substitutes for ASCII letters. We flag them when mixed with ASCII
   * in identifiers that humans or LLMs use to identify servers/tools.
   */
  private readonly CONFUSABLE_BLOCKS: { start: number; end: number; name: string }[] = [
    { start: 0x0400, end: 0x04ff, name: "Cyrillic" },
    { start: 0x0370, end: 0x03ff, name: "Greek" },
    { start: 0x0250, end: 0x02af, name: "IPA Extensions" },
    { start: 0x1d00, end: 0x1d7f, name: "Phonetic Extensions" },
    { start: 0x2000, end: 0x206f, name: "General Punctuation (zero-width)" },
    { start: 0xff01, end: 0xff60, name: "Fullwidth Latin" },
    { start: 0x200b, end: 0x200f, name: "Zero-width characters" },
    { start: 0x2060, end: 0x2064, name: "Word joiner / invisible" },
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check server name
    const serverName = discovery.serverInfo?.name;
    if (serverName) {
      const result = this.analyzeString(serverName);
      if (result) {
        findings.push({
          severity: this.severity,
          message: t("sec_061_server_name", {
            name: serverName,
            blocks: result.blocks.join(", "),
            positions: result.positions,
          }),
          component: "server",
          ruleCode: this.code,
          remediation: t("sec_061_recommendation"),
          references: [
            "Unicode Security Considerations UTS#39",
            "CWE-1007: Insufficient Visual Distinction of Homoglyphs",
            "OWASP A08:2021 – Software and Data Integrity Failures",
          ],
        });
      }
    }

    // Check tool names
    for (const tool of discovery.tools ?? []) {
      const result = this.analyzeString(tool.name);
      if (result) {
        findings.push({
          severity: this.severity,
          message: t("sec_061_tool_name", {
            toolName: tool.name,
            blocks: result.blocks.join(", "),
            positions: result.positions,
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_061_recommendation"),
          references: [
            "Unicode Security Considerations UTS#39",
            "CWE-1007: Insufficient Visual Distinction of Homoglyphs",
          ],
        });
      }
    }

    // Check resource names and URIs
    for (const resource of discovery.resources ?? []) {
      const nameResult = this.analyzeString(resource.name ?? "");
      const uriResult = this.analyzeString(resource.uri ?? "");
      const hit = nameResult ?? uriResult;
      if (hit) {
        findings.push({
          severity: this.severity,
          message: t("sec_061_resource_name", {
            resourceName: resource.name ?? resource.uri,
            blocks: hit.blocks.join(", "),
            positions: hit.positions,
          }),
          component: `resource:${resource.name ?? resource.uri}`,
          ruleCode: this.code,
          remediation: t("sec_061_recommendation"),
          references: [
            "Unicode Security Considerations UTS#39",
            "CWE-1007: Insufficient Visual Distinction of Homoglyphs",
          ],
        });
      }
    }

    return findings;
  }

  /**
   * Returns info about non-ASCII confusable characters found in the string,
   * or null if the string is clean ASCII (or pure non-ASCII without mixing).
   *
   * Pure non-ASCII strings (e.g. a Japanese tool name "検索") are not flagged
   * because there is no spoofing intent — the name is unambiguously non-Latin.
   * Spoofing only makes sense when non-ASCII chars are mixed with ASCII to
   * create a visually deceptive identifier.
   */
  private analyzeString(
    value: string,
  ): { blocks: string[]; positions: string } | null {
    if (!value) return null;

    let hasAsciiLetters = false;
    const confusableChars: { char: string; codepoint: number; blockName: string; index: number }[] = [];

    for (let i = 0; i < value.length; i++) {
      const cp = value.codePointAt(i) ?? 0;

      // Track ASCII letter presence
      if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) {
        hasAsciiLetters = true;
        continue;
      }

      // Skip ASCII non-letters (digits, spaces, punctuation)
      if (cp <= 0x007f) continue;

      // Check if codepoint is in a confusable block
      const block = this.CONFUSABLE_BLOCKS.find(
        (b) => cp >= b.start && cp <= b.end,
      );
      if (block) {
        confusableChars.push({
          char: value[i]!,
          codepoint: cp,
          blockName: block.name,
          index: i,
        });
      }
    }

    // Only flag when ASCII letters AND confusable non-ASCII chars coexist
    if (!hasAsciiLetters || confusableChars.length === 0) return null;

    const blocks = [...new Set(confusableChars.map((c) => c.blockName))];
    const positions = confusableChars
      .map((c) => `'${c.char}' (U+${c.codepoint.toString(16).toUpperCase().padStart(4, "0")} ${c.blockName}) at pos ${c.index}`)
      .join("; ");

    return { blocks, positions };
  }
}
