/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Examples Command
 *
 * Show usage examples and quick start guide
 */

import chalk from "chalk";
import { t } from "@mcp-verify/shared";

export async function runExamplesAction() {
  console.log(chalk.bold("\n📚 " + t("examples_title") + "\n"));
  console.log(chalk.cyan("1. " + t("basic_validation")));
  console.log(chalk.gray("   mcp-verify validate http://localhost:3000"));
  console.log(chalk.dim("   → " + t("example_1_desc") + "\n"));

  console.log(chalk.cyan("2. " + t("security_scan")));
  console.log(
    chalk.gray("   mcp-verify validate http://localhost:3000 --html"),
  );
  console.log(chalk.dim("   → " + t("example_2_desc") + "\n"));

  console.log(chalk.cyan("3. " + t("load_testing")));
  console.log(
    chalk.gray(
      "   mcp-verify stress http://localhost:3000 --users 10 --duration 30",
    ),
  );
  console.log(chalk.dim("   → " + t("example_3_desc") + "\n"));

  console.log(chalk.cyan("4. " + t("interactive_playground")));
  console.log(chalk.gray("   mcp-verify play http://localhost:3000"));
  console.log(chalk.dim("   → " + t("example_4_desc") + "\n"));

  console.log(chalk.cyan("5. " + t("ci_cd_integration")));
  console.log(
    chalk.gray("   mcp-verify validate http://localhost:3000 --format sarif"),
  );
  console.log(chalk.dim("   → " + t("example_5_desc") + "\n"));

  console.log(chalk.cyan("6. " + t("mock_server")));
  console.log(chalk.gray("   mcp-verify mock --port 3000"));
  console.log(chalk.dim("   → " + t("example_6_desc") + "\n"));

  console.log(chalk.bold("📖 " + t("detailed_guides") + ":"));
  console.log(chalk.gray("   examples/use-cases/basic-validation.md"));
  console.log(chalk.gray("   examples/use-cases/security-scan.md"));
  console.log(chalk.gray("   examples/use-cases/stress-testing.md"));
  console.log(chalk.gray("   examples/use-cases/ci-cd-integration.md\n"));

  console.log(chalk.bold("🎯 " + t("test_servers") + ":"));
  console.log(
    chalk.gray(
      "   node examples/servers/dummy-server.js    (" +
        t("working_server") +
        ")",
    ),
  );
  console.log(
    chalk.gray(
      "   node examples/servers/broken-server.js   (" +
        t("error_testing_server") +
        ")\n",
    ),
  );
}
