/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-033: Recursive Agent Loop Exploitation
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools that can create infinite recursion or loops when chained
 * with other tools, causing resource exhaustion.
 *
 * Detection:
 * Static:
 * - Tools that can call themselves (self-referencing)
 * - Missing depth/recursion limits in parameters
 * - Tool chains without cycle detection
 *
 * Fuzzer:
 * - Test circular tool dependencies
 * - Measure recursion depth and timeout behavior
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Loop Prevention
 * - CWE-674: Uncontrolled Recursion
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class RecursiveAgentLoopRule implements ISecurityRule {
  code = "SEC-033";
  name = "Recursive Agent Loop Exploitation";
  severity: "high" = "high";

  private readonly RECURSIVE_KEYWORDS = [
    "recursive",
    "recurse",
    "loop",
    "iterate",
    "repeat",
    "retry",
    "traverse",
    "walk",
    "nested",
    "chain",
  ];

  private readonly DEPTH_LIMIT_PARAMS = [
    "max_depth",
    "depth_limit",
    "max_recursion",
    "recursion_limit",
    "max_iterations",
    "iteration_limit",
    "max_loops",
    "loop_limit",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isRecursive = this.hasRecursivePattern(tool);

      if (isRecursive) {
        const hasDepthLimit = this.hasDepthLimitParameter(tool);

        if (!hasDepthLimit) {
          findings.push({
            severity: this.severity,
            message: t("sec_033_recursive_loop", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_033_recommendation"),
            references: [
              "Multi-Agent Security Framework (MASF) 2024 - Loop Prevention",
              "CWE-674: Uncontrolled Recursion",
              "OWASP - Denial of Service Prevention",
            ],
          });
        }
      }
    }

    // Check for potential circular dependencies
    const circularChains = this.detectCircularChains(discovery.tools);
    if (circularChains.length > 0) {
      findings.push({
        severity: "high",
        message: t("sec_033_circular_chain", {
          chain: circularChains[0].join(" -> "),
        }),
        component: "tool-chain",
        ruleCode: this.code,
        remediation: t("sec_033_chain_recommendation"),
        references: [
          "Multi-Agent Security Framework (MASF) 2024 - Loop Prevention",
        ],
      });
    }

    return findings;
  }

  private hasRecursivePattern(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.RECURSIVE_KEYWORDS.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasDepthLimitParameter(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    const paramNames = Object.keys(tool.inputSchema.properties).map((p) =>
      p.toLowerCase(),
    );

    return this.DEPTH_LIMIT_PARAMS.some((param) => paramNames.includes(param));
  }

  private detectCircularChains(tools: McpTool[]): string[][] {
    const chains: string[][] = [];

    // Build dependency graph
    const dependencies = new Map<string, Set<string>>();

    for (const tool of tools) {
      const deps = this.extractToolDependencies(tool, tools);
      if (deps.length > 0) {
        dependencies.set(tool.name, new Set(deps));
      }
    }

    // Detect cycles using DFS
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const dfs = (toolName: string, path: string[]): boolean => {
      visited.add(toolName);
      recursionStack.add(toolName);
      path.push(toolName);

      const deps = dependencies.get(toolName);
      if (deps) {
        for (const dep of deps) {
          if (!visited.has(dep)) {
            if (dfs(dep, [...path])) {
              return true;
            }
          } else if (recursionStack.has(dep)) {
            // Found cycle
            const cycleStart = path.indexOf(dep);
            chains.push([...path.slice(cycleStart), dep]);
            return true;
          }
        }
      }

      recursionStack.delete(toolName);
      return false;
    };

    for (const toolName of dependencies.keys()) {
      if (!visited.has(toolName)) {
        dfs(toolName, []);
      }
    }

    return chains;
  }

  private extractToolDependencies(
    tool: McpTool,
    allTools: McpTool[],
  ): string[] {
    const dependencies: string[] = [];

    if (!tool.description) {
      return dependencies;
    }

    const descLower = tool.description.toLowerCase();

    for (const otherTool of allTools) {
      if (otherTool.name === tool.name) continue;

      const otherNameLower = otherTool.name.toLowerCase();
      if (descLower.includes(otherNameLower)) {
        dependencies.push(otherTool.name);
      }
    }

    return dependencies;
  }
}
