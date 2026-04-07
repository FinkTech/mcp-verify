/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { DiagnosticRunner } from "../diagnostic-runner";
import {
  IDiagnosticCheck,
  DiagnosticResult,
} from "../diagnostic-check.interface";

class MockCheck implements IDiagnosticCheck {
  constructor(
    public readonly name: string,
    public readonly description: string,
    private result: DiagnosticResult,
  ) {}

  async run(): Promise<DiagnosticResult> {
    return this.result;
  }
}

describe("DiagnosticRunner", () => {
  let runner: DiagnosticRunner;

  beforeEach(() => {
    runner = new DiagnosticRunner();
  });

  it("should execute registered checks", async () => {
    const check1 = new MockCheck("Check 1", "Desc 1", {
      name: "Check 1",
      status: "pass",
      message: "OK",
      durationMs: 10,
    });
    const check2 = new MockCheck("Check 2", "Desc 2", {
      name: "Check 2",
      status: "fail",
      message: "Error",
      durationMs: 15,
    });

    runner.register(check1);
    runner.register(check2);

    const results = await runner.runAll();

    expect(results).toHaveLength(2);
    expect(results[0].status).toBe("pass");
    expect(results[1].status).toBe("fail");
  });
});
