/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Init Command
 *
 * Create default configuration file
 */

import chalk from "chalk";
import fs from "fs";
import path from "path";
import { DEFAULT_CONFIG } from "@mcp-verify/core";
import { t } from "@mcp-verify/shared";

export async function runInitAction() {
  const configPath = path.join(process.cwd(), "mcp-verify.config.json");
  if (fs.existsSync(configPath)) {
    console.log(chalk.yellow(t("config_exists")), configPath);
    return;
  }

  const configContent = JSON.stringify(DEFAULT_CONFIG, null, 2);
  fs.writeFileSync(configPath, configContent);
  console.log(chalk.green("✓ " + t("config_created")), configPath);
  console.log(chalk.gray(t("edit_to_customize")));
}
