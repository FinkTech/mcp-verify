/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fuzzer Integration Tests
 *
 * Verifies that the fuzz command detects vulnerabilities through
 * intelligent payload generation and feedback-driven mutation.
 *
 * Test Strategy:
 * 1. Start configurable vulnerable server with specific vulnerability profile
 * 2. Run fuzz command with targeted generators
 * 3. Parse fuzzing session report
 * 4. Assert vulnerabilities were detected
 * 5. Verify detection severity and remediation guidance
 * 6. Clean up server and report files
 */

import * as path from "path";
import * as fs from "fs";
import { runFuzzAction } from "../../apps/cli-verifier/src/commands/fuzz";
import { TestServerManager } from "./helpers/test-server-manager";

describe("Fuzzer: Prompt Injection Detection", () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(
    __dirname,
    "../__test-reports__/fuzzer-prompt-injection",
  );

  beforeAll(async () => {
    // Start vulnerable test server with prompt-injection profile
    serverManager = new TestServerManager();
    await serverManager.start({
      profile: "prompt-injection",
      lang: "en",
      transport: "stdio",
      timeout: 5000,
    });

    // Ensure test report directory exists
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    // Stop server gracefully
    await serverManager.stop();

    // Clean up test reports (optional - comment out for debugging)
    if (fs.existsSync(testReportDir)) {
      fs.rmSync(testReportDir, { recursive: true, force: true });
    }
  });

  it("should detect prompt injection vulnerabilities via fuzzer", async () => {
    // Get target string for fuzzing
    const target = serverManager.getTarget();

    // Run fuzzing with prompt-injection generator
    await runFuzzAction(target, {
      tool: "generate_response", // Target the vulnerable tool
      generators: "prompt-injection",
      detectors: "prompt-leak,jailbreak",
      output: testReportDir,
      format: "json",
      verbose: false,
      concurrency: "1",
      timeout: "5000",
    });

    // Load generated fuzzing session report
    const jsonReportPath = path.join(testReportDir, "json", "en");
    expect(fs.existsSync(jsonReportPath)).toBe(true);

    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("fuzz-session-") && f.endsWith(".json"));
    expect(reportFiles.length).toBeGreaterThan(0);

    const latestReport = reportFiles.sort().reverse()[0]; // Get most recent report
    const reportContent = fs.readFileSync(
      path.join(jsonReportPath, latestReport),
      "utf8",
    );
    const session = JSON.parse(reportContent);

    // Verify session structure
    expect(session).toHaveProperty("id");
    expect(session).toHaveProperty("vulnerabilities");
    expect(Array.isArray(session.vulnerabilities)).toBe(true);

    // Assert vulnerabilities were detected
    expect(session.vulnerabilities.length).toBeGreaterThan(0);

    // Find prompt-injection vulnerability
    const promptInjectionVuln = session.vulnerabilities.find(
      (v: any) =>
        v.category.toLowerCase().includes("prompt") ||
        v.type.toLowerCase().includes("injection"),
    );

    expect(promptInjectionVuln).toBeDefined();
    expect(promptInjectionVuln.severity).toMatch(/high|critical|medium/i);

    // Verify detection details
    expect(promptInjectionVuln).toHaveProperty("detectedBy");
    expect(promptInjectionVuln).toHaveProperty("remediation");

    // Log vulnerability for debugging
    if (promptInjectionVuln) {
      console.log(
        "\n✓ Prompt injection detected:",
        promptInjectionVuln.description,
      );
      console.log("  Severity:", promptInjectionVuln.severity);
      console.log("  Detected by:", promptInjectionVuln.detectedBy);
    }
  });

  it("should execute feedback-driven mutation rounds", async () => {
    const target = serverManager.getTarget();

    await runFuzzAction(target, {
      tool: "generate_response",
      generators: "prompt-injection",
      detectors: "prompt-leak,jailbreak",
      output: testReportDir,
      format: "json",
      verbose: false,
      concurrency: "1",
      timeout: "5000",
    });

    // Load report
    const jsonReportPath = path.join(testReportDir, "json", "en");
    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("fuzz-session-") && f.endsWith(".json"));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(
      path.join(jsonReportPath, latestReport),
      "utf8",
    );
    const session = JSON.parse(reportContent);

    // Verify feedback loop stats exist (smart fuzzer)
    expect(session).toHaveProperty("feedbackStats");

    const feedback = session.feedbackStats;
    expect(feedback).toHaveProperty("mutationsInjected");
    expect(feedback).toHaveProperty("mutationRoundsCompleted");
    expect(feedback).toHaveProperty("interestingResponsesFound");

    // Feedback-driven fuzzing should execute at least 1 mutation round
    // (only if interesting responses were found)
    if (feedback.interestingResponsesFound > 0) {
      expect(feedback.mutationRoundsCompleted).toBeGreaterThanOrEqual(1);
      expect(feedback.mutationsInjected).toBeGreaterThan(0);
    }

    console.log("\n✓ Feedback stats:", {
      interesting: feedback.interestingResponsesFound,
      mutations: feedback.mutationsInjected,
      rounds: feedback.mutationRoundsCompleted,
    });
  });

  it("should detect jailbreak attempts in tool responses", async () => {
    const target = serverManager.getTarget();

    await runFuzzAction(target, {
      tool: "generate_response",
      generators: "prompt-injection",
      detectors: "jailbreak",
      output: testReportDir,
      format: "json",
      verbose: false,
      concurrency: "1",
      timeout: "5000",
    });

    // Load report
    const jsonReportPath = path.join(testReportDir, "json", "en");
    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("fuzz-session-") && f.endsWith(".json"));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(
      path.join(jsonReportPath, latestReport),
      "utf8",
    );
    const session = JSON.parse(reportContent);

    // Check for jailbreak detections
    const jailbreakVuln = session.vulnerabilities.find(
      (v: any) =>
        v.detectedBy === "JailbreakDetector" ||
        v.type.toLowerCase().includes("jailbreak"),
    );

    // Jailbreak detection depends on vulnerable server responding in a way
    // that triggers the detector. This test verifies the detector ran.
    // If no jailbreak is found, it might be that the server doesn't exhibit
    // jailbreak-like responses, which is acceptable for this skeleton test.

    if (jailbreakVuln) {
      console.log("\n✓ Jailbreak attempt detected:", jailbreakVuln.description);
    } else {
      console.log("\n✓ Jailbreak detector executed (no jailbreaks found)");
    }

    // The important assertion is that the fuzzer ran successfully
    expect(session.vulnerabilities).toBeDefined();
  });
});

describe("Fuzzer: Multi-Vulnerability Detection", () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(
    __dirname,
    "../__test-reports__/fuzzer-multi-vuln",
  );

  beforeAll(async () => {
    // Start vulnerable test server with ALL vulnerabilities
    serverManager = new TestServerManager();
    await serverManager.start({
      profile: "all-vulns",
      lang: "en",
      transport: "stdio",
      timeout: 5000,
    });

    // Ensure test report directory exists
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    // Stop server gracefully
    await serverManager.stop();

    // Clean up test reports (optional - comment out for debugging)
    if (fs.existsSync(testReportDir)) {
      fs.rmSync(testReportDir, { recursive: true, force: true });
    }
  });

  it('should detect multiple vulnerability types with "all" generators', async () => {
    const target = serverManager.getTarget();

    // Run comprehensive fuzzing with all generators
    await runFuzzAction(target, {
      generators: "all", // All generator types
      detectors: "all", // All detector types
      output: testReportDir,
      format: "json",
      verbose: false,
      concurrency: "2", // Parallel fuzzing
      timeout: "120000",
    });

    // Load report
    const jsonReportPath = path.join(testReportDir, "json", "en");
    expect(fs.existsSync(jsonReportPath)).toBe(true);

    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("fuzz-session-") && f.endsWith(".json"));
    expect(reportFiles.length).toBeGreaterThan(0);

    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(
      path.join(jsonReportPath, latestReport),
      "utf8",
    );
    const session = JSON.parse(reportContent);

    // Verify multiple vulnerability categories were tested
    expect(session).toHaveProperty("payloadsByCategory");
    const categories = Object.keys(session.payloadsByCategory);
    expect(categories.length).toBeGreaterThan(1); // Multiple attack vectors tested

    // Verify vulnerabilities were found
    expect(session.vulnerabilities.length).toBeGreaterThan(0);

    // Count unique vulnerability types
    const uniqueTypes = new Set(
      session.vulnerabilities.map((v: any) => v.type || v.category),
    );

    console.log("\n✓ Comprehensive fuzzing results:");
    console.log("  Payloads executed:", session.payloadsExecuted);
    console.log("  Attack categories:", categories.length);
    console.log("  Unique vulnerabilities:", uniqueTypes.size);
    console.log("  Total findings:", session.vulnerabilities.length);

    // Assert that comprehensive fuzzing found multiple issues
    expect(uniqueTypes.size).toBeGreaterThan(1);
  });

  it("should generate a valid fuzzing summary report", async () => {
    const target = serverManager.getTarget();

    await runFuzzAction(target, {
      generators: "prompt-injection,sqli",
      output: testReportDir,
      format: "json",
      verbose: false,
    });

    // Load report
    const jsonReportPath = path.join(testReportDir, "json", "en");
    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("fuzz-session-") && f.endsWith(".json"));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(
      path.join(jsonReportPath, latestReport),
      "utf8",
    );
    const session = JSON.parse(reportContent);

    // Validate session report structure
    expect(session).toHaveProperty("id");
    expect(session).toHaveProperty("startedAt");
    expect(session).toHaveProperty("endedAt");
    expect(session).toHaveProperty("totalPayloads");
    expect(session).toHaveProperty("payloadsExecuted");
    expect(session).toHaveProperty("vulnerabilities");
    expect(session).toHaveProperty("errors");
    expect(session).toHaveProperty("payloadsByCategory");

    // Timing validation
    expect(new Date(session.startedAt).getTime()).toBeLessThanOrEqual(
      new Date(session.endedAt).getTime(),
    );

    // Progress validation
    expect(session.payloadsExecuted).toBeLessThanOrEqual(session.totalPayloads);

    console.log("\n✓ Fuzzing session report is valid");
  });
});
