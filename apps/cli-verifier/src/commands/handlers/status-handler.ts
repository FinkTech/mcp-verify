/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Status Command Handler
 *
 * Displays comprehensive workspace health information:
 * - Active context (name, target, profile)
 * - Environment variables (loaded from .env)
 * - Last generated report
 * - MCP server connection status (via testHandshake())
 */

import chalk from "chalk";
import path from "path";
import type { ShellSession } from "../interactive/session";
import { WorkspaceHealthChecker } from "../managers/workspace-health-checker";
import type {
  WorkspaceHealth,
  ConnectionStatus,
} from "../types/workspace-health";

/**
 * Display comprehensive workspace status
 *
 * @param session - Shell session
 */
export async function handleStatus(session: ShellSession): Promise<void> {
  console.log(chalk.bold.white("\n  Workspace Status\n"));

  // Perform health check
  const health = await WorkspaceHealthChecker.check(
    session.state.activeContextName,
    session.getActiveContext(),
    session.state.environment,
  );

  // Display each section
  renderContextSection(health);
  renderEnvironmentSection(health);
  renderLastReportSection(health);
  await renderConnectionSection(health);

  console.log(); // Empty line at end
}

/**
 * Render context information section
 */
function renderContextSection(health: WorkspaceHealth): void {
  console.log(chalk.bold("  Context:"));
  console.log(`    Active:  ${chalk.cyan(health.context.name)}`);

  if (health.context.target) {
    console.log(`    Target:  ${chalk.dim(health.context.target)}`);
  } else {
    console.log(`    Target:  ${chalk.dim("(not set)")}`);
  }

  console.log(`    Profile: ${chalk.yellow(health.context.profile)}`);
  console.log();
}

/**
 * Render environment variables section
 * SECURITY: Shows key names but never shows values (they're sensitive)
 */
function renderEnvironmentSection(health: WorkspaceHealth): void {
  console.log(chalk.bold("  Environment:"));

  if (health.environment.loaded) {
    const sourceFileName = health.environment.sourceFile
      ? path.basename(health.environment.sourceFile)
      : "unknown";

    console.log(`    Source:  ${chalk.green(sourceFileName)}`);
    console.log(
      `    Keys:    ${chalk.dim(health.environment.keysFound.length + " loaded")}`,
    );

    if (health.environment.keysFound.length > 0) {
      // SECURITY: Only show key names, NEVER show values
      // Mask sensitive key names to make it clear they contain secrets
      const safeKeys = health.environment.keysFound.map((key) => {
        if (
          key.includes("API_KEY") ||
          key.includes("TOKEN") ||
          key.includes("SECRET")
        ) {
          return `${key} ${chalk.yellow("[PROTECTED]")}`;
        }
        return key;
      });
      const keys = safeKeys.join(", ");
      console.log(`      ${chalk.dim(keys)}`);
    }
  } else {
    console.log(`    Source:  ${chalk.dim("(no .env file found)")}`);
    console.log(`    Keys:    ${chalk.dim("0 loaded")}`);
  }

  console.log();
}

/**
 * Render last report section
 */
function renderLastReportSection(health: WorkspaceHealth): void {
  console.log(chalk.bold("  Last Report:"));

  if (health.lastReport.exists) {
    console.log(`    Path:    ${chalk.cyan(health.lastReport.path)}`);

    if (health.lastReport.timestamp) {
      const date = new Date(health.lastReport.timestamp);
      const formatted = date.toLocaleString();
      console.log(`    Time:    ${chalk.dim(formatted)}`);
    }
  } else {
    console.log(`    ${chalk.dim("(no reports found)")}`);
  }

  console.log();
}

/**
 * Render MCP server connection section
 */
async function renderConnectionSection(health: WorkspaceHealth): Promise<void> {
  console.log(chalk.bold("  Target Connection:"));

  const { connection } = health;

  // Render status with color coding
  const statusDisplay = renderConnectionStatus(connection.status);
  console.log(`    Status:  ${statusDisplay}`);

  // Render additional details based on status
  switch (connection.status) {
    case "connected":
      if (connection.serverName) {
        console.log(`    Server:  ${chalk.dim(connection.serverName)}`);
      }
      if (connection.protocolVersion) {
        console.log(`    Version: ${chalk.dim(connection.protocolVersion)}`);
      }
      if (connection.responseTime !== undefined) {
        console.log(
          `    Time:    ${chalk.dim(connection.responseTime + "ms")}`,
        );
      }
      break;

    case "unreachable":
      if (connection.error) {
        console.log(`    Error:   ${chalk.dim(connection.error)}`);
      }
      if (connection.responseTime !== undefined) {
        console.log(
          `    Time:    ${chalk.dim(connection.responseTime + "ms")}`,
        );
      }
      break;

    case "protocol_mismatch":
      console.log(
        `    ${chalk.yellow("Server responded but protocol is not valid MCP")}`,
      );
      if (connection.error) {
        console.log(`    Error:   ${chalk.dim(connection.error)}`);
      }
      break;

    case "not_configured":
      console.log(`    ${chalk.dim("No target configured")}`);
      console.log(`    ${chalk.dim('Use "set target <path>" to configure')}`);
      break;
  }

  console.log();
}

/**
 * Render connection status with appropriate color coding
 *
 * @param status - Connection status
 * @returns Formatted status string
 */
function renderConnectionStatus(status: ConnectionStatus): string {
  switch (status) {
    case "connected":
      return chalk.green("● Connected");

    case "unreachable":
      return chalk.red("● Unreachable");

    case "protocol_mismatch":
      return chalk.yellow("⚠ Protocol Mismatch");

    case "not_configured":
      return chalk.yellow("○ Not Configured");

    default:
      return chalk.dim("○ Unknown");
  }
}
