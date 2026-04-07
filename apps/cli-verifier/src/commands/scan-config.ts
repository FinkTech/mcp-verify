/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Scan Config Command
 *
 * Pre-execution security scanner for MCP configuration files.
 * Detects malicious patterns in .mcp.json and .claude/settings.json BEFORE execution.
 *
 * Implements Block D detection: AI Weaponization & Supply Chain MCP
 * - SEC-053: Malicious Config File (CVE-2025-59536)
 * - SEC-054: API Endpoint Hijacking (CVE-2026-21852)
 *
 * Usage:
 *   mcp-verify scan-config .mcp.json
 *   mcp-verify scan-config .claude/settings.json
 *   mcp-verify scan-config --all  # Scan all config files in project
 */

import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import ora from "ora";
import { t } from "@mcp-verify/shared";
import { MaliciousConfigFileRule } from "@mcp-verify/core/domain/security/rules/malicious-config-file.rule";
import type { SecurityFinding } from "@mcp-verify/core";

/**
 * Scan configuration file for malicious patterns
 */
export async function runScanConfigAction(
  configPath: string,
  options: {
    all?: boolean;
    quiet?: boolean;
  },
): Promise<number> {
  const rule = new MaliciousConfigFileRule();

  // If --all flag, scan common config file locations
  if (options.all) {
    return await scanAllConfigFiles(rule, options.quiet || false);
  }

  // Otherwise scan specific file
  const spinner = !options.quiet
    ? ora(`Scanning ${configPath}...`).start()
    : null;

  try {
    const findings = rule.evaluateConfigFile(configPath);

    spinner?.stop();

    // Display results
    displayScanResults(configPath, findings, options.quiet || false);

    // Return with appropriate code
    const hasCritical = findings.some((f) => f.severity === "critical");
    if (hasCritical) {
      console.log(
        chalk.red.bold(
          "\n⚠️  CRITICAL FINDINGS DETECTED - DO NOT EXECUTE THIS PROJECT\n",
        ),
      );
      return 2; // Critical security exit code
    }

    return findings.length > 0 ? 1 : 0;
  } catch (error) {
    spinner?.fail("Scan failed");
    console.error(
      chalk.red(
        `Error scanning config: ${error instanceof Error ? error.message : String(error)}`,
      ),
    );
    return 1;
  }
}

/**
 * Scan all common MCP config file locations
 */
async function scanAllConfigFiles(
  rule: MaliciousConfigFileRule,
  quiet: boolean,
): Promise<number> {
  const cwd = process.cwd();

  const configPaths = [
    path.join(cwd, ".mcp.json"),
    path.join(cwd, ".claude", "settings.json"),
    path.join(cwd, "mcp-verify.config.json"),
    // Add more common locations as needed
  ];

  console.log(
    chalk.bold.white(`\n  Scanning MCP config files in: ${chalk.cyan(cwd)}\n`),
  );

  let totalFindings = 0;
  let criticalCount = 0;

  for (const configPath of configPaths) {
    if (!fs.existsSync(configPath)) {
      if (!quiet) {
        console.log(
          chalk.dim(
            `  ○ ${path.relative(cwd, configPath)} - not found (skipped)`,
          ),
        );
      }
      continue;
    }

    const findings = rule.evaluateConfigFile(configPath);

    if (findings.length === 0 || findings.every((f) => f.severity === "info")) {
      console.log(chalk.green(`  ✓ ${path.relative(cwd, configPath)} - clean`));
      continue;
    }

    console.log(
      chalk.yellow(
        `  ⚠️  ${path.relative(cwd, configPath)} - ${findings.length} finding(s)`,
      ),
    );

    // Display findings for this file
    displayScanResults(configPath, findings, true); // compact mode

    totalFindings += findings.length;
    criticalCount += findings.filter((f) => f.severity === "critical").length;
  }

  // Summary
  console.log(chalk.bold.white("\n  Scan Summary:"));
  console.log(`  Total findings: ${totalFindings}`);
  console.log(`  Critical: ${chalk.red(criticalCount.toString())}`);

  if (criticalCount > 0) {
    console.log(
      chalk.red.bold(
        "\n⚠️  CRITICAL FINDINGS DETECTED - DO NOT EXECUTE THIS PROJECT\n",
      ),
    );
    return 2;
  } else if (totalFindings > 0) {
    console.log(
      chalk.yellow("\n⚠️  Warnings found. Review before proceeding.\n"),
    );
    return 1;
  } else {
    console.log(chalk.green("\n✓ All config files are clean.\n"));
    return 0;
  }
}

/**
 * Display scan results in formatted output
 */
function displayScanResults(
  configPath: string,
  findings: SecurityFinding[],
  compact: boolean,
): void {
  if (findings.length === 0) {
    console.log(chalk.green(`\n✓ Config file is clean: ${configPath}\n`));
    return;
  }

  console.log(chalk.bold.white("\n  Config Security Report:"));
  console.log(chalk.dim("  ─".repeat(40)));
  console.log(`  File: ${chalk.cyan(configPath)}`);

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");
  const mediumFindings = findings.filter((f) => f.severity === "medium");
  const lowFindings = findings.filter((f) => f.severity === "low");
  const infoFindings = findings.filter((f) => f.severity === "info");

  const status =
    criticalFindings.length > 0
      ? chalk.red.bold("❌ MALICIOUS")
      : highFindings.length > 0
        ? chalk.yellow("⚠️  SUSPICIOUS")
        : chalk.green("✓ Clean");

  console.log(`  Status: ${status}`);

  if (criticalFindings.length > 0) {
    console.log(`  ${chalk.red.bold("Critical")}: ${criticalFindings.length}`);
  }
  if (highFindings.length > 0) {
    console.log(`  ${chalk.yellow("High")}: ${highFindings.length}`);
  }
  if (mediumFindings.length > 0) {
    console.log(`  ${chalk.yellow("Medium")}: ${mediumFindings.length}`);
  }
  if (lowFindings.length > 0) {
    console.log(`  ${chalk.dim("Low")}: ${lowFindings.length}`);
  }

  console.log(chalk.dim("  ─".repeat(40)));

  // Display each finding
  for (const finding of findings) {
    if (finding.severity === "info" && compact) {
      continue; // Skip info findings in compact mode
    }

    const code = finding.ruleCode || "SEC-UNKNOWN";
    const severityLabel =
      finding.severity === "critical"
        ? chalk.red.bold(`[${code}] CRITICAL`)
        : finding.severity === "high"
          ? chalk.yellow(`[${code}] HIGH`)
          : finding.severity === "medium"
            ? chalk.yellow(`[${code}] MEDIUM`)
            : chalk.dim(`[${code}] ${finding.severity.toUpperCase()}`);

    console.log(`\n  ${severityLabel}`);
    console.log(`    ${finding.message}`);

    if (finding.remediation && !compact) {
      console.log(chalk.dim(`    → ${finding.remediation}`));
    }
  }

  console.log(chalk.dim("  ─".repeat(40)));

  if (!compact && criticalFindings.length > 0) {
    console.log(
      chalk.red.bold(
        "\n  Recommendation: DO NOT execute this project. Report to security team.\n",
      ),
    );
  }
}
