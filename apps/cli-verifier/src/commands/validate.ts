/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Validate Command
 *
 * Comprehensive validation of MCP servers including:
 * - Handshake, discovery, schema validation
 * - Security scanning, quality analysis
 * - Report generation (JSON, HTML, Markdown, SARIF)
 */

import ora from "ora";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import { ZodError } from "zod";
import {
  MCPValidator,
  ITransport,
  Language,
  generateDisclaimer,
  generateMetadata,
  getShortDisclaimer,
  ConfigLoader,
  enhancedReporter,
  Logger,
} from "@mcp-verify/core";
import { SmartFuzzer } from "@mcp-verify/core/use-cases/fuzzer/fuzzer";
import { DenoSandbox } from "@mcp-verify/core/infrastructure/sandbox/deno-sandbox";
import { BaselineManager } from "@mcp-verify/core/domain/baseline/baseline-manager";
import { SarifGenerator } from "@mcp-verify/core/domain/reporting/sarif-generator";
import {
  t,
  setLanguage,
  getCurrentLanguage,
  ReportingService,
  ReportFormat,
  captureGitInfo,
} from "@mcp-verify/shared";
import {
  createTransport,
  detectTransportType,
} from "../utils/transport-factory";
import { configureLogging } from "../utils/logging-helper";
import { registerCleanup } from "../utils/cleanup-handlers";
import { printOutput } from "../utils/output-helper";
import {
  formatError,
  createLogger,
  PathValidator,
  URLValidator,
} from "@mcp-verify/shared";

/**
 * Simple word wrap utility that preserves indentation for terminal output.
 */
function wrapText(text: string, indent: number = 4): string {
  const columns = process.stdout.columns || 80;
  const maxWidth = columns - indent;
  const words = text.split(" ");
  const lines: string[] = [];
  let currentLine = "";

  words.forEach((word) => {
    if ((currentLine + word).length > maxWidth) {
      lines.push(currentLine.trim());
      currentLine = word + " ";
    } else {
      currentLine += word + " ";
    }
  });
  lines.push(currentLine.trim());

  const indentation = " ".repeat(indent);
  return lines.join("\n" + indentation);
}

export async function runValidationAction(
  target: string,
  options: Record<string, unknown>,
) {
  // Respect --lang option
  if (options.lang) {
    setLanguage(options.lang as Language);
  }

  // Check disclaimer before proceeding
  const { checkDisclaimer } = await import("../utils/disclaimer-manager");
  const accepted = await checkDisclaimer("validate");

  if (!accepted) {
    console.log(chalk.yellow(t("disclaimer_aborted")));
    return 0;
  }

  // Determine if we should suppress spinners (--quiet or --json-stdout)
  const isQuiet = Boolean(options.quiet || options.jsonStdout);
  const log = createLogger(isQuiet);
  const spinner = isQuiet ? null : ora(t("initializing")).start();
  let validator: MCPValidator | null = null;
  let transport: ITransport | null = null;

  // Configure logging based on verbose flag
  configureLogging(Boolean(options.verbose));

  try {
    // Determine transport type
    const transportType =
      (options.transport as string | undefined) || detectTransportType(target);
    if (spinner)
      spinner.text = `${t("connecting")} ${String(transportType).toUpperCase()}...`;

    // SECURITY WARNING: Private IP detection
    if (
      URLValidator.isURL(target) &&
      URLValidator.isPrivateOrLocalhost(target)
    ) {
      const reason = URLValidator.getPrivateIPReason(target);
      if (spinner) {
        spinner.warn(chalk.yellow(t("warn_private_ip")));
        spinner.info(chalk.gray(`   ${target} (${reason})`));
        spinner.info(chalk.gray(t("info_local_safe")));
        spinner.info(chalk.gray(t("info_cloud_caution")));
        spinner.start(
          t("connecting") + " " + transportType.toUpperCase() + "...",
        );
      } else if (!isQuiet) {
        log.log(chalk.yellow(`\n${t("warn_private_ip")}`));
        log.log(chalk.gray(`   ${target} (${reason})`));
        log.log(chalk.gray(t("info_local_safe")));
        log.log(chalk.gray(`${t("info_cloud_caution")}\n`));
      }
    }

    // Sandbox initialization
    let sandbox = undefined;
    if (options.sandbox && transportType === "stdio") {
      sandbox = new DenoSandbox({
        allowRead: ["."],
        allowEnv: true,
        allowNet: [],
      });
      if (spinner) {
        spinner.info(chalk.blue(t("sandbox_active")));
        spinner.start(
          t("connecting") + " " + transportType.toUpperCase() + "...",
        );
      }
    } else if (!options.sandbox && transportType === "stdio") {
      // SECURITY WARNING: Running without sandbox
      if (spinner) {
        spinner.warn(chalk.yellow(t("warn_no_sandbox")));
        spinner.info(chalk.gray(t("info_direct_exec")));
        spinner.info(chalk.gray(t("info_trust_only")));
        spinner.start(
          t("connecting") + " " + transportType.toUpperCase() + "...",
        );
      } else if (!isQuiet) {
        log.log(chalk.yellow(`\n${t("warn_no_sandbox")}`));
        log.log(chalk.gray(t("info_direct_exec")));
        log.log(chalk.gray(`${t("info_trust_only")}\n`));
      }
    }

    // Parse environment variables
    const envVars: Record<string, string> = {};
    if (options.env && Array.isArray(options.env)) {
      options.env.forEach((pair: string) => {
        const [key, ...rest] = pair.split("=");
        const value = rest.join("=");
        if (key) envVars[key] = value || "";
      });
    }

    // Create transport using factory
    transport = createTransport(target, {
      transportType: transportType as "stdio" | "http" | "sse",
      envVars,
      sandbox,
      verbose: Boolean(options.verbose),
      timeout: 30000,
      lang: getCurrentLanguage(),
    });

    // Initialize validator with optional semantic check and LLM provider
    const enableSemanticCheck = Boolean(options.semanticCheck);
    const llmProvider = options.llm as string | undefined;

    if (llmProvider) {
      // User specified LLM provider explicitly
      if (spinner) {
        spinner.info(
          chalk.blue(t("llm_analysis_using", { provider: llmProvider })),
        );
        spinner.start();
      }
    } else if (enableSemanticCheck) {
      // Legacy --semantic-check flag (deprecated in favor of --llm)
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) {
        if (spinner) {
          spinner.warn(chalk.yellow(t("llm_semantic_check_deprecated")));
          spinner.info(chalk.dim(t("llm_examples_header")));
          spinner.info(chalk.dim(t("llm_example_anthropic")));
          spinner.info(chalk.dim(t("llm_example_ollama")));
          spinner.info(chalk.dim(t("llm_example_openai")));
          spinner.info(chalk.cyan(t("llm_continuing_without")));
          spinner.start();
        }
      } else {
        if (spinner) {
          spinner.info(
            chalk.blue("🧠 LLM semantic analysis enabled (legacy mode)"),
          );
          spinner.start();
        }
      }
    }

    validator = new MCPValidator(
      transport,
      options.config as string | undefined,
      {
        enableSemanticCheck,
        llmProvider,
        rules: options.rules as string | undefined,
        excludeRules: options.excludeRules as string | undefined,
        minSeverity: options.minSeverity as string | undefined,
      },
    );

    // Show loaded configuration
    const configPath = ConfigLoader.getConfigFilePath();
    const loadError = ConfigLoader.getLoadError();

    if (loadError) {
      const errorMsg = t("config_load_error");
      if (spinner) {
        spinner.warn(chalk.yellow(errorMsg));
        // We can't print multi-line details easily in a spinner workflow without stopping/restarting or logging.
        // Best approach: Log warning, then details.
      } else if (!isQuiet) {
        log.warn(chalk.yellow(errorMsg));
      }

      // Print detailed error
      if (loadError instanceof ZodError) {
        loadError.issues.forEach((issue) => {
          if (spinner)
            spinner.info(
              chalk.dim(`   • ${issue.path.join(".")}: ${issue.message}`),
            );
          else
            log.log(
              chalk.dim(`   • ${issue.path.join(".")}: ${issue.message}`),
            );
        });
      } else {
        if (spinner) spinner.info(chalk.dim(`   • ${loadError.message}`));
        else log.log(chalk.dim(`   • ${loadError.message}`));
      }

      // Resume spinner if needed
      if (spinner) spinner.start();
    } else if (configPath) {
      const relativePath = path.relative(process.cwd(), configPath);
      if (spinner) {
        spinner.info(
          chalk.blue(t("config_using_path", { path: relativePath })),
        );
        spinner.start();
      } else if (!isQuiet) {
        log.info(chalk.blue(t("config_using_path", { path: relativePath })));
      }
    } else {
      if (spinner) {
        spinner.info(chalk.gray(t("config_using_default")));
        spinner.start();
      } else if (!isQuiet) {
        log.info(chalk.gray(t("config_using_default")));
      }
    }

    // Register cleanup handler
    registerCleanup(async () => {
      if (validator) await validator.cleanup();
    });

    if (spinner) spinner.text = t("testing_handshake");
    const handshakeResult = await validator.testHandshake();

    if (!handshakeResult.success) {
      if (spinner) spinner.fail(t("failed_connect_server"));
      log.log("");
      log.error(chalk.red.bold("❌ " + t("connection_failed") + "\n"));
      log.error(chalk.red(t("error") + ": ") + handshakeResult.error);
      log.log("");
      log.log(chalk.yellow.bold("💡 " + t("troubleshooting_tips") + ":\n"));
      log.log(chalk.gray("1. ") + t("tip_check_server"));
      log.log(chalk.dim(t("example_ps_command")));
      log.log("");
      log.log(chalk.gray("2. ") + t("tip_verify_url"));
      log.log(chalk.dim(t("example_curl_command") + " " + target));
      log.log("");
      log.log(chalk.gray("3. ") + t("tip_try_transport"));
      log.log(
        chalk.dim(
          t("example_validate_command") + " " + target + " --transport stdio",
        ),
      );
      log.log("");
      log.log(chalk.gray("4. ") + t("tip_run_doctor"));
      log.log(chalk.dim(t("example_doctor_command") + " " + target));
      log.log("");
      if (validator) validator.cleanup();
      return;
    }

    if (spinner) spinner.text = t("discovering");
    const discoveryResult = await validator.discoverCapabilities();

    if (spinner) spinner.text = t("validating_schema");
    const validationResult = await validator.validateSchema();

    let fuzzingResult = undefined;
    if (options.fuzz) {
      if (spinner) spinner.text = t("running_fuzzer");
      const fuzzer = new SmartFuzzer(transport);
      fuzzingResult = await fuzzer.run(discoveryResult);
    }

    if (spinner) spinner.text = t("generating_report");
    const baseReport = await validator.generateReport({
      handshake: handshakeResult,
      discovery: discoveryResult,
      validation: validationResult,
      fuzzing: fuzzingResult,
    });

    // --- PREPARE FINAL DATA ---
    const llmUsed = Boolean(llmProvider);
    const modulesExecuted: Array<
      "security" | "quality" | "fuzzing" | "protocol"
    > = ["security", "quality"];
    if (options.fuzz) modulesExecuted.push("fuzzing");

    // Update baseReport with final disclaimer and git info before signing
    baseReport.disclaimer = generateDisclaimer({
      language: getCurrentLanguage(),
      llmUsed,
      llmProvider: llmProvider as "anthropic" | "openai" | "ollama" | undefined,
    });

    const gitInfo = captureGitInfo();
    if (gitInfo) {
      baseReport.gitInfo = gitInfo;
    }

    // --- TIER S ENHANCEMENT ---
    const metrics = validator.getMetrics();
    const health = await validator.getHealthStatus();
    const auditTrail = Logger.getInstance().getAuditTrail();

    const report = enhancedReporter.generateEnhancedReport(
      baseReport,
      metrics,
      health,
      auditTrail,
      {
        llmUsed,
        llmProvider: llmProvider as
          | "anthropic"
          | "openai"
          | "ollama"
          | undefined,
        modulesExecuted,
        gitInfo: baseReport.gitInfo,
      },
    );

    // --- REPORT GENERATION (Centralized via ReportingService) ---
    // SECURITY FIX: Validate output path to prevent path traversal attacks
    const rawOutputDir = String(options.output || "./reports");
    const outputDir = path.resolve(
      PathValidator.validateOutputPath(rawOutputDir, "."),
    );
    const lang = getCurrentLanguage();
    const reportFormat = String(options.format || "json");

    // Determine which formats to generate
    const formats: ReportFormat[] = ["json", "markdown"]; // Always generate JSON and Markdown
    if (options.html !== false) {
      formats.push("html");
    }
    if (reportFormat === "sarif") {
      formats.push("sarif");
    }

    // Use centralized ReportingService
    const savedReports = await ReportingService.saveReport(
      { kind: "validation", data: report },
      {
        outputDir,
        formats,
        language: lang,
        filenamePrefix: "mcp-report",
        organizeByFormat: true, // validate uses organized subdirectories
      },
    );

    // Extract paths for display
    const reportPath = savedReports.paths.json || "";
    const htmlReportPath = savedReports.paths.html || "";
    const mdReportPath = savedReports.paths.markdown || "";
    const sarifPath = savedReports.paths.sarif || "";

    // Create baseline/comparison directories (used later for baseline management)
    const baselineDir = path.join(outputDir, "baseline", lang);
    const comparisonDir = path.join(outputDir, "comparison", lang);
    fs.mkdirSync(baselineDir, { recursive: true });
    fs.mkdirSync(comparisonDir, { recursive: true });

    // Log any errors from report generation
    for (const error of savedReports.errors) {
      if (spinner)
        spinner.warn(
          chalk.yellow(`Could not generate ${error.format}: ${error.message}`),
        );
    }

    if (spinner) spinner.succeed(t("validation_complete"));

    // --- OUTPUT STRATEGY ---
    // If user wants stdout output (for piping), output JSON/SARIF and suppress visual report
    const outputDirStr = String(options.output || "./reportes");
    const outputToStdout =
      outputDirStr === "-" ||
      outputDirStr === "stdout" ||
      Boolean(options.jsonStdout);
    const formatStr = String(options.format || "json");
    const isFormatOnly =
      (formatStr === "json" || formatStr === "sarif") && !options.html;

    if (outputToStdout || (isFormatOnly && !process.stdout.isTTY)) {
      // Output to stdout for piping (CI/CD friendly)
      if (reportFormat === "sarif") {
        const sarifContent = SarifGenerator.generate(report);
        printOutput(sarifContent);
      } else {
        // Default to JSON
        printOutput(report);
      }
      return; // Skip visual report
    }

    // --- CLI OUTPUT (Visual Report to stderr) ---
    process.stderr.write(
      "\n" + chalk.bold(t("validation_report") + ":") + "\n",
    );
    process.stderr.write(chalk.gray("─".repeat(50)) + "\n");
    log.log(`${t("server")}: ${chalk.cyan(report.server_name)}`);
    log.log(
      `${t("status")}: ${report.status === "valid" ? chalk.green("✓ " + t("status_valid")) : chalk.red("✗ " + t("status_invalid"))}`,
    );
    log.log(`${t("protocol")}: ${report.protocol_version}`);
    log.log(
      `${t("tools")}: ${report.tools.count} (${chalk.green(report.tools.valid)} ${t("valid_label")})`,
    );

    // Protocol Compliance
    if (report.protocolCompliance) {
      const pc = report.protocolCompliance;
      let pcColor = chalk.green;
      if (pc.score < 80) pcColor = chalk.yellow;
      if (pc.score < 50) pcColor = chalk.red;

      log.log(`${t("protocol_compliance")}: ${pcColor(pc.score + "/100")}`);
      if (!pc.passed) {
        log.log(chalk.red("  " + t("jsonrpc_violations")));
        pc.issues.forEach((i) =>
          log.log(chalk.red(`  - [${i.code}] ${i.message}`)),
        );
      }
    }

    // Quality
    const qualityScore = report.quality.score;
    let qColor = chalk.green;
    if (qualityScore < 50) qColor = chalk.red;
    else if (qualityScore < 80) qColor = chalk.yellow;
    log.log(`${t("quality_score")}: ${qColor(qualityScore + "/100")}`);
    if (report.quality.issues.length > 0) {
      log.log(
        chalk.yellow(
          `  ${report.quality.issues.length} ${t("semantic_issues")}`,
        ),
      );
    }

    // Fuzzing
    if (report.fuzzing) {
      log.log(
        `${t("fuzzing_label")}: ${chalk.cyan(report.fuzzing.totalTests)} ${t("tests_label")}`,
      );
      if (report.fuzzing.crashes > 0) {
        log.log(
          chalk.bgRed.white.bold(
            `  ${t("crashes_detected")}: ${report.fuzzing.crashes}  `,
          ),
        );
      } else if (report.fuzzing.failedTests > 0) {
        log.log(
          chalk.yellow(
            `  ${t("failures_label")}: ${report.fuzzing.failedTests}`,
          ),
        );
      } else {
        log.log(chalk.green(`  ${t("all_tests_passed_label")}`));
      }
    }

    log.log(`${t("duration_ms")}: ${report.duration_ms}ms`);

    // Security Audit
    log.log(chalk.bold("\n" + t("security_audit") + ":"));
    let scoreColor = chalk.green;
    if (report.security.score < 70) scoreColor = chalk.red;
    else if (report.security.score < 90) scoreColor = chalk.yellow;

    log.log(
      `${t("score")}: ${scoreColor(report.security.score + "/100")} (${scoreColor(report.security.level)})`,
    );

    if (report.badges) {
      log.log(`${t("badge")}: ${chalk.blue(report.badges.url)}`);
    }

    if (report.security.findings.length > 0) {
      report.security.findings.forEach((finding) => {
        let severityColor = chalk.white;
        if (finding.severity === "critical") severityColor = chalk.red.bold;
        if (finding.severity === "high") severityColor = chalk.red;
        if (finding.severity === "medium") severityColor = chalk.yellow;

        const prefix = `  • [${severityColor(finding.severity.toUpperCase())}] `;
        // Indent based on prefix length (approx 15 chars for "[CRITICAL]")
        const indentSize = finding.severity === "critical" ? 15 : 11;
        const wrappedMessage = wrapText(finding.message, indentSize);
        log.log(`${prefix}${wrappedMessage}`);
      });
    }

    log.log(chalk.gray("─".repeat(50)));
    log.log(`${t("json_label")}: ${chalk.cyan(reportPath)}`);
    log.log(
      `${chalk.bold(t("markdown_label"))}: ${chalk.magenta(mdReportPath)}`,
    );
    if (htmlReportPath)
      log.log(`${t("html_label")}: ${chalk.blue(htmlReportPath)}`);
    if (sarifPath) log.log(`${t("sarif_label")}: ${chalk.magenta(sarifPath)}`);
    log.log("");

    // Show disclaimer
    log.log(chalk.dim("⚠️  " + getShortDisclaimer(getCurrentLanguage())));
    if (llmUsed) {
      log.log(
        chalk.dim(
          "🤖 " +
            t("disclaimer_llm_notice").replace("{provider}", llmProvider || ""),
        ),
      );
    }
    log.log("");

    // --- Baseline Comparison ---
    let shouldFailFromBaseline = false;

    // Helper to resolve baseline path (use baselineDir if only a filename is provided)
    const resolveBaselinePath = (p: string) => {
      if (path.isAbsolute(p) || p.includes("/") || p.includes("\\")) {
        return PathValidator.validateBaselinePath(p);
      }
      return path.join(baselineDir, p);
    };

    // Save baseline if requested
    if (options.saveBaseline) {
      const baselinePath = resolveBaselinePath(String(options.saveBaseline));
      BaselineManager.saveBaseline(report, baselinePath);
      log.log(chalk.green(`✓ ${t("baseline_saved_at")}: ${baselinePath}`));
    }

    // Compare against baseline if requested
    if (options.compareBaseline) {
      const baselinePath = resolveBaselinePath(String(options.compareBaseline));
      const baseline = BaselineManager.loadBaseline(baselinePath);

      if (!baseline) {
        log.log(chalk.yellow(t("baseline_not_found", { path: baselinePath })));
        log.log(
          chalk.dim(
            t("baseline_not_found_tip", {
              path: String(options.compareBaseline),
            }),
          ),
        );
      } else {
        const comparison = BaselineManager.compare(report, baseline);

        // Save comparison report
        const comparisonPath = path.join(
          comparisonDir,
          `mcp-comparison-${savedReports.timestamp}.json`,
        );
        fs.writeFileSync(comparisonPath, JSON.stringify(comparison, null, 2));

        log.log("");
        log.log(chalk.bold("📊 " + t("baseline_comparison_title") + ":"));
        log.log(chalk.gray("─".repeat(50)));
        log.log(comparison.message);
        log.log("");
        log.log(
          `${t("security_audit")} ${t("score")}: ${baseline.securityScore} → ${comparison.current.securityScore} ${comparison.delta.securityScore >= 0 ? chalk.green(`(+${comparison.delta.securityScore})`) : chalk.red(`(${comparison.delta.securityScore})`)}`,
        );
        log.log(
          `${t("quality")} ${t("score")}:  ${baseline.qualityScore} → ${comparison.current.qualityScore} ${comparison.delta.qualityScore >= 0 ? chalk.green(`(+${comparison.delta.qualityScore})`) : chalk.red(`(${comparison.delta.qualityScore})`)}`,
        );

        if (comparison.delta.newCriticalFindings > 0) {
          log.log(
            chalk.red.bold(
              `⚠️  ${t("baseline_new_critical", { count: comparison.delta.newCriticalFindings })}`,
            ),
          );
        }
        if (comparison.delta.newHighFindings > 0) {
          log.log(
            chalk.yellow(
              `⚠️  ${t("baseline_new_high", { count: comparison.delta.newHighFindings })}`,
            ),
          );
        }
        if (comparison.delta.fixedFindings > 0) {
          log.log(
            chalk.green(
              `✓ ${t("baseline_findings_fixed", { count: comparison.delta.fixedFindings })}`,
            ),
          );
        }

        log.log(chalk.gray("─".repeat(50)));
        log.log(`${t("comparison_saved_at")}: ${chalk.cyan(comparisonPath)}`);
        log.log("");

        // Determine if we should fail build based on baseline
        shouldFailFromBaseline = BaselineManager.shouldFailBuild(comparison, {
          failOnCritical: true,
          failOnDegradation: Boolean(options.failOnDegradation),
          allowedScoreDrop: Number(options.allowedScoreDrop || 5),
        });

        if (shouldFailFromBaseline) {
          log.log(chalk.red.bold("❌ " + t("baseline_build_failed")));
        }
      }
    }

    // Exit with appropriate code for CI/CD
    if (shouldFailFromBaseline) {
      return 2; // Critical degradation
    } else {
      // Check if there are CRITICAL security findings
      // We count them explicitly to be safe, in case the report object doesn't have the counter pre-calculated
      const criticalFindingsCount = report.security?.findings
        ? report.security.findings.filter((f) => f.severity === "critical")
            .length
        : 0;

      const hasCriticalFindings = criticalFindingsCount > 0;

      // SECURITY GATE: Critical findings always fail the build (Exit Code 2)
      if (hasCriticalFindings) {
        return 2;
      }

      // If no critical security issues, check protocol/functional validity
      if (report.status !== "valid") {
        return 1;
      }
    }

    return 0; // Success
  } catch (error) {
    if (spinner) spinner.fail(t("validation_failed"));
    log.log("");
    log.error(chalk.red.bold("❌ " + t("validation_failed") + "\n"));
    log.error(
      chalk.red(t("error") + ": ") +
        (error instanceof Error ? error.message : String(error)),
    );
    log.log("");
    log.log(chalk.yellow.bold("💡 " + t("common_solutions") + ":\n"));

    const errorMsg = String(
      error instanceof Error ? error.message : error,
    ).toLowerCase();

    if (
      errorMsg.includes("econnrefused") ||
      errorMsg.includes("connection refused")
    ) {
      log.log(chalk.gray("• ") + t("server_not_running"));
      log.log(chalk.dim("  " + t("try_prefix") + " " + t("tip_check_process")));
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_verify_port") + "\n"),
      );
    } else if (errorMsg.includes("timeout")) {
      log.log(chalk.gray("• ") + t("server_slow"));
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_increase_timeout")),
      );
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_check_logs") + "\n"),
      );
    } else if (errorMsg.includes("enotfound") || errorMsg.includes("dns")) {
      log.log(chalk.gray("• ") + t("dns_error"));
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_check_spelling")),
      );
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_ping_hostname") + "\n"),
      );
    } else if (errorMsg.includes("parse") || errorMsg.includes("json")) {
      log.log(chalk.gray("• ") + t("invalid_json"));
      log.log(
        chalk.dim("  " + t("try_prefix") + " " + t("tip_check_implementation")),
      );
      log.log(
        chalk.dim(
          "  " + t("try_prefix") + " " + t("tip_use_verbose_raw") + "\n",
        ),
      );
    } else {
      log.log(chalk.gray("• ") + t("unexpected_error"));
      log.log(chalk.dim("  " + t("try_prefix") + " " + t("tip_verbose")));
      log.log(
        chalk.dim(
          "  " + t("try_prefix") + " mcp-verify doctor " + target + "\n",
        ),
      );
    }

    log.log(chalk.bold("🔍 " + t("need_help") + ""));
    log.log(
      chalk.gray("   " + t("label_run") + " ") +
        chalk.cyan("mcp-verify doctor " + target),
    );
    log.log(
      chalk.gray("   " + t("label_docs") + " ") +
        chalk.cyan("mcp-verify examples"),
    );
    log.log(
      chalk.gray("   " + t("label_issues") + " ") +
        chalk.cyan("https://github.com/FinkTech/mcp-verify/issues\n"),
    );
    return 1;
  } finally {
    if (validator) await validator.cleanup();
  }
}
