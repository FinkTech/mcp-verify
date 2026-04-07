/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { MockServer } from "@mcp-verify/core/use-cases/mock/mock-server";
import { MCPValidator, HttpTransport } from "@mcp-verify/core";

describe("Validator Integration Test", () => {
  let server: MockServer;
  let validator: MCPValidator;
  const PORT = 3001; // Use different port to avoid conflicts

  beforeAll(async () => {
    server = new MockServer(PORT);
    await server.start();
  });

  afterAll(() => {
    server.stop();
  });

  beforeEach(() => {
    const transport = HttpTransport.create(`http://localhost:${PORT}`);
    validator = new MCPValidator(transport);
  });

  afterEach(() => {
    if (validator) validator.cleanup();
  });

  it("should successfully handshake with the mock server", async () => {
    const result = await validator.testHandshake();
    expect(result.success).toBe(true);
    expect(result.protocolVersion).toBe("2024-11-05");
  });

  it("should discover capabilities", async () => {
    await validator.testHandshake();
    const result = await validator.discoverCapabilities();

    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.resources.length).toBeGreaterThan(0);
    expect(result.prompts.length).toBeGreaterThan(0);
  });

  it("should validate tool schema", async () => {
    await validator.testHandshake();
    await validator.discoverCapabilities();
    const result = await validator.validateSchema();

    expect(result.schemaValid).toBe(true);
    expect(result.toolsInvalid).toBe(0);
  });
});
