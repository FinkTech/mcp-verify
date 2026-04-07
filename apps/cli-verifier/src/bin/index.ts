/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify CLI - Entry Point (Refactored)
 *
 * This file orchestrates all CLI commands by importing and registering them.
 * Business logic is delegated to individual command modules.
 */

import { Command } from "commander";
import chalk from "chalk";
import updateNotifier from "update-notifier";
import {
  initLanguage,
  getCurrentLanguage,
  t,
  detectLanguage,
  setLanguage,
} from "@mcp-verify/shared";
import { Logger as InfrastructureLogger } from "@mcp-verify/core";
import { ASCII_ART } from "@mcp-verify/core/domain/reporting/assets";

// Import package.json for version info
import * as packageJson from "../../../../package.json";

// Command handlers
import { runValidationAction } from "../commands/validate";
import { runStressAction } from "../commands/stress";
import { runMockAction } from "../commands/mock";
import { runInitAction } from "../commands/init";
import { runDashboardAction } from "../commands/dashboard";
import { runPlaygroundAction } from "../commands/play";
import { runProxyAction } from "../commands/proxy";
import { runDoctorAction } from "../commands/doctor";
import { runExamplesAction } from "../commands/examples";
import { runFuzzAction } from "../commands/fuzz";
import { runDisclaimersAction } from "../commands/disclaimers";
import { runScanConfigAction } from "../commands/scan-config";
import { startInteractiveMode } from "../commands/interactive";

// Initialize language and silence infrastructure logger by default
initLanguage();
const logger = InfrastructureLogger.getInstance();
logger.configure({ enableConsole: false });

// --- Helper for handling exit codes in one-shot mode (Type-Safe) ---
const wrapAction = <A extends unknown[]>(
  action: (...args: A) => Promise<number | void>,
) => {
  return async (...args: A) => {
    try {
      const exitCode = await action(...args);
      if (typeof exitCode === "number") {
        process.exit(exitCode);
      }
    } catch (error) {
      console.error(
        chalk.red(
          `\n  ✗ Fatal error: ${error instanceof Error ? error.message : String(error)}\n`,
        ),
      );
      process.exit(1);
    }
  };
};

// Update notifier - checks for new versions once per day
try {
  const notifier = updateNotifier({
    pkg: {
      name: packageJson.name,
      version: packageJson.version,
    },
    updateCheckInterval: 1000 * 60 * 60 * 24, // Check once per day
  });

  // Show notification if update available (non-blocking)
  notifier.notify({
    message: `Update available: ${chalk.dim("{currentVersion}")} → ${chalk.green("{latestVersion}")}\nRun ${chalk.cyan("npm install -g mcp-verify")} to update`,
    boxenOptions: {
      padding: 1,
      margin: 1,
      borderColor: "yellow",
      borderStyle: "round",
    },
  });
} catch {
  // Silently fail - don't let update check crash the CLI
}

const program = new Command();

// --- Program Configuration ---
program
  .name("mcp-verify")
  .description(t("cli_description"))
  .version(
    packageJson.version,
    "-v, --version",
    "Show version with Yogui mascot",
  )
  // Global flags available to all commands
  .option("-q, --quiet", t("option_quiet_desc"))
  .option("--json-stdout", t("option_json_stdout_desc"))
  .option("--no-color", t("option_no_color_desc"))
  .option("-l, --lang <lang>", t("option_lang_desc"), detectLanguage())
  .option("--mascot", "Show Yogui mascot in output (opt-in)")
  .on("option:lang", (lang) => {
    setLanguage(lang);
  });

// --- Commands ---

// Validate Command
program
  .command("validate <target>")
  .description(t("cmd_validate_desc"))
  .option("-t, --transport <type>", t("option_transport_type"))
  .option("-o, --output <path>", t("option_output_directory"), "./reports")
  .option("-c, --config <path>", t("mcp_param_config_path_desc"))
  .option("--html", t("option_generate_html"))
  .option("--format <type>", t("option_report_format"), "json")
  .option("-e, --env <pairs...>", t("option_env_variables"))
  .option("--fuzz", t("option_enable_fuzzing"))
  .option("--sandbox", t("option_sandbox"))
  .option(
    "--rules <list>",
    "Comma-separated list of rule blocks to execute (e.g., OWASP,MCP,A)",
  )
  .option(
    "--exclude-rules <list>",
    "Comma-separated list of rule blocks or IDs to exclude (e.g., SEC-001,Weaponization)",
  )
  .option(
    "--min-severity <level>",
    "Minimum severity level to report (info, low, medium, high, critical)",
  )
  .option("--semantic-check", t("option_semantic_check_desc"))
  .option("--llm <provider:model>", t("option_llm_desc"))
  .option("--save", t("option_save_scan"))
  .option("--verbose", t("option_verbose_logging"))
  .option("--save-baseline <path>", t("option_save_baseline_desc"))
  .option("--compare-baseline <path>", t("option_compare_baseline_desc"))
  .option("--fail-on-degradation", t("option_fail_on_degradation_desc"))
  .option(
    "--allowed-score-drop <number>",
    t("option_allowed_score_drop_desc"),
    "5",
  )
  .action(wrapAction(runValidationAction));

// Stress Test Command
program
  .command("stress <target>")
  .description(t("cmd_stress_desc"))
  .option("-t, --transport <type>", t("option_transport_type"))
  .option("-u, --users <number>", t("option_concurrent_users"), "5")
  .option("-d, --duration <seconds>", t("option_test_duration"), "10")
  .option("--verbose", t("option_verbose_logging"))
  .action(wrapAction(runStressAction));

// Mock Server Command
program
  .command("mock")
  .description(t("cmd_mock_desc"))
  .option("-p, --port <number>", t("option_port_listen"), "3000")
  .option("--timeout <ms>", t("option_proxy_timeout"))
  .action(wrapAction(runMockAction));

// Init Config Command
program
  .command("init")
  .description(t("cmd_init_desc"))
  .action(wrapAction(runInitAction));

// Dashboard Command
program
  .command("dashboard <target>")
  .description(t("cmd_dashboard_desc"))
  .option("-t, --transport <type>", t("option_transport_stdio_http"))
  .option("-p, --port <number>", t("option_dashboard_port"), "5173")
  .option("--timeout <ms>", t("option_proxy_timeout"))
  .action(wrapAction(runDashboardAction));

// Playground Command
program
  .command("play <target>")
  .description(t("cmd_playground_desc"))
  .option("-p, --port <number>", t("option_port_listen"), "8080")
  .option("-t, --transport <type>", t("option_transport_type"))
  .option("--list-only", t("option_list_only"))
  .action(wrapAction(runPlaygroundAction));

// Proxy Command
program
  .command("proxy <target>")
  .description(t("cmd_proxy_desc"))
  .option("-p, --port <number>", t("option_port_listen"), "8080")
  .option("--timeout <ms>", t("option_proxy_timeout"))
  .option("--log-file <path>", t("option_proxy_log_file"))
  .action(wrapAction(runProxyAction));

// Doctor Command
program
  .command("doctor [target]")
  .description(t("cmd_doctor_desc"))
  .option("-t, --transport <type>", t("option_transport_stdio_http"))
  .option("--watch", t("option_watch_desc"))
  .option("--verbose", t("option_verbose_doctor_desc"))
  .option("--html", t("option_generate_html"))
  .option("--md", t("option_generate_md"))
  .option("--json", t("option_generate_json"))
  .option("-o, --output <path>", t("option_output_directory"), "./reports")
  .option("--show-history", t("option_show_history_desc"))
  .option("--fix-integrity", t("option_fix_integrity_desc"))
  .option("--clean-history <n>", t("option_clean_history_desc"), parseInt)
  .action(wrapAction(runDoctorAction));

// Examples Command
program
  .command("examples")
  .description(t("cmd_examples_desc"))
  .action(wrapAction(runExamplesAction));

// Disclaimers Command
program
  .command("disclaimers")
  .description("Manage security disclaimer preferences")
  .option("--reset", "Reset disclaimer preferences")
  .option(
    "--type <type>",
    "Specific disclaimer type (fuzz, stress, proxy, validate)",
  )
  .action(wrapAction(runDisclaimersAction));

// Fuzz Command
program
  .command("fuzz <target>")
  .description(t("cmd_fuzz_desc"))
  .option("-t, --transport <type>", t("option_transport_type"))
  .option("-c, --concurrency <number>", t("option_fuzz_concurrency"), "1")
  .option("--timeout <ms>", t("option_fuzz_timeout"), "5000")
  .option("--tool <name>", t("option_fuzz_tool"), "echo")
  .option("--param <name>", t("option_fuzz_param"), "input")
  .option("--generators <list>", t("option_fuzz_generators"), "all")
  .option("--detectors <list>", t("option_fuzz_detectors"), "all")
  .option("--stop-on-first", t("option_fuzz_stop_on_first"))
  .option("--fingerprint", t("option_fuzz_fingerprint"))
  .option("--verbose", t("option_verbose_logging"))
  .option("-o, --output <path>", t("option_output_directory"))
  .option("--format <type>", t("option_fuzz_format_sarif"), "json")
  .option("-H, --header <header...>", t("option_http_header"))
  .action(wrapAction(runFuzzAction));

// Scan-Config Command (Block D: Supply Chain Security)
program
  .command("scan-config [path]")
  .description(t("cmd_scan_config_desc"))
  .option("--all", t("option_scan_all_configs"))
  .option("-q, --quiet", t("option_quiet_desc"))
  .action(wrapAction(runScanConfigAction));

// Check if running in one-shot mode (has a command)
const hasCommand = process.argv
  .slice(2)
  .some(
    (arg) =>
      !arg.startsWith("-") &&
      [
        "validate",
        "stress",
        "mock",
        "init",
        "dashboard",
        "play",
        "proxy",
        "doctor",
        "examples",
        "fuzz",
        "disclaimers",
        "scan-config",
      ].includes(arg),
  );

const hasHelpFlag =
  process.argv.includes("--help") || process.argv.includes("-h");
const hasVersionFlag =
  process.argv.includes("--version") || process.argv.includes("-V");

// Custom --version handler with Yogui ASCII art
if (hasVersionFlag) {
  console.log(chalk.cyan(ASCII_ART.version(packageJson.version)));
  process.exit(0);
}

// If has command or help flags, run in one-shot mode
if (hasCommand || hasHelpFlag) {
  program.parse(process.argv);
} else {
  // Default: Start interactive mode
  const lang = initLanguage();

  console.log(
    chalk.cyan(`
╔═════════════════════════════════════════════════════════════════════════════════╗
║                                                                                 ║
║   ███╗   ███╗ ██████╗██████╗     ██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗  ║
║   ████╗ ████║██╔════╝██╔══██╗    ██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝  ║
║   ██╔████╔██║██║     ██████╔╝    ██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝   ║
║   ██║╚██╔╝██║██║     ██╔═══╝     ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝    ║
║   ██║ ╚═╝ ██║╚██████╗██║          ╚████╔╝ ███████╗██║  ██║██║██║        ██║     ║
║   ╚═╝     ╚═╝ ╚═════╝╚╚═╝           ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝    ║
║                                                                                 ║
╚═════════════════════════════════════════════════════════════════════════════════╝
`),
  );

  console.log(chalk.bold.white(`  🛡️  ${t("welcome_title")}`));
  console.log(chalk.gray(`  Version: ${packageJson.version}`));
  console.log(chalk.gray(`  ${t("created_by")} Fink`));
  console.log(
    chalk.dim(`  📧 ${t("email_label").padEnd(10)}: `) +
      chalk.cyan("hello.finksystems@gmail.com"),
  );
  console.log(
    chalk.dim(`  🌐 ${t("github_label").trim().padEnd(10)}: `) +
      chalk.cyan("github.com/FinkTech"),
  );
  console.log(
    chalk.dim(`  💼 ${t("linkedin_label").trim().padEnd(10)}: `) +
      chalk.cyan("linkedin.com/in/ariel-fink"),
  );

  console.log(
    chalk.yellow(
      `\n  ⚠️  Disclaimer: ${t("cli_disclaimer_independent") || "This is an independent open-source tool."}`,
    ),
  );
  console.log(
    chalk.gray(
      `      ${t("cli_disclaimer_affiliation") || "Not affiliated with Anthropic or the Model Context Protocol organization."}`,
    ),
  );

  // Start interactive mode by default
  startInteractiveMode();
}
