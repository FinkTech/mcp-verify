/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import path from "path";
import fs from "fs";
import { execSync } from "child_process";
import { SandboxService } from "@mcp-verify/core/use-cases/sandbox/sandbox.service";
import { SandboxOptions } from "@mcp-verify/core/use-cases/sandbox/types";

const TEMP_DIR = path.resolve(__dirname, "../temp_sandbox_service_test");

if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

// Check if Deno is available
function isDenoAvailable(): boolean {
  try {
    execSync("deno --version", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const describeOrSkip = isDenoAvailable() ? describe : describe.skip;

describeOrSkip("SandboxService Integration Tests", () => {
  let service: SandboxService;
  let defaultOptions: SandboxOptions;

  jest.setTimeout(60000);

  beforeAll(() => {
    service = new SandboxService();
    defaultOptions = {
      cwd: TEMP_DIR,
      timeoutMs: 10000,
      memoryLimitMb: 128,
      capabilities: {
        allowRead: [TEMP_DIR],
        allowWrite: [TEMP_DIR],
        allowNet: [],
        allowEnv: [],
      },
    };
  });

  afterAll(() => {
    if (fs.existsSync(TEMP_DIR)) {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
    }
  });

  test("✅ Should pass end-to-end with safe code", async () => {
    const code = `console.log("Safe and Sound");`;
    const result = await service.runSafe(code, defaultOptions);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Safe and Sound");
  });

  test("🚫 Should fail STATIC analysis for dangerous code (eval)", async () => {
    const code = `eval("console.log('hacked')");`;

    await expect(service.runSafe(code, defaultOptions)).rejects.toMatchObject({
      stage: "STATIC_ANALYSIS",
      message: expect.stringContaining("Prohibited usage of 'eval'"),
    });
  });

  test("🚫 Should fail STATIC analysis for dangerous code (new Function)", async () => {
    const code = `const f = new Function("return 1");`;

    await expect(service.runSafe(code, defaultOptions)).rejects.toMatchObject({
      stage: "STATIC_ANALYSIS",
      message: expect.stringContaining("Prohibited usage of 'new Function'"),
    });
  });

  test("🛡️ Should fail TAINT analysis if critical secrets leak", async () => {
    // Simulamos un leak CRÍTICO que el servicio debe interceptar
    const code = `console.log("Here is a secret: AWS_ACCESS_KEY_ID = AKIA_TEST_12345");`;

    try {
      const result = await service.runSafe(code, defaultOptions);

      // If we got here, the promise resolved instead of rejecting
      // This is a failure - let's debug why
      console.error(
        "[DEBUG] Test failed - Promise resolved when it should reject",
      );
      console.error("[DEBUG] Result:", JSON.stringify(result, null, 2));
      console.error("[DEBUG] Taint check:", result.taintCheck);

      // Fail the test explicitly
      fail(
        "Expected promise to reject with TAINT_ANALYSIS error, but it resolved",
      );
    } catch (error: any) {
      // Expected path - the promise should reject
      expect(error.stage).toBe("TAINT_ANALYSIS");
      expect(error.message).toContain("Critical secret leakage");
    }
  });
});
