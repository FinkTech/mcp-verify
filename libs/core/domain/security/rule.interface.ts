/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import {
  DiscoveryResult,
  SecurityFinding,
} from "../mcp-server/entities/validation.types";

/**
 * Represents a security rule that can evaluate an MCP server discovery result.
 * Rules are the core unit of the security analysis engine.
 */
export interface ISecurityRule {
  /**
   * Unique identifier for the rule (e.g., 'SEC-001').
   * Follows the format: SEC-{XXX}.
   */
  code: string;

  /**
   * Human-readable name of the rule.
   */
  name: string;

  /**
   * Detailed description of what the rule checks for.
   */
  description?: string;

  /**
   * URL to external documentation (OWASP, CWE, etc.) for further reading.
   */
  helpUri?: string;

  /**
   * List of tags associated with the rule (e.g., 'OWASP-LLM01', 'CWE-78').
   */
  tags?: string[];

  /**
   * Evaluates the discovery result against this security rule.
   *
   * @param discovery - The result of the MCP server discovery phase, containing tools, resources, and prompts.
   * @returns An array of security findings. Returns empty array if no vulnerabilities are found.
   */
  evaluate(discovery: DiscoveryResult): SecurityFinding[];
}

/**
 * Metadata associated with a security rule for reporting purposes.
 */
export interface ISecurityRuleMetadata {
  /** Description of the rule. */
  description?: string;
  /** External references URLs. */
  references?: string[];
  /** Category of the vulnerability (e.g., 'Injection', 'Auth'). */
  category?: string;
  /** Suggested remediation steps for the user. */
  remediation?: string;
}

/**
 * Composite interface combining rule logic and metadata.
 */
export interface ISecurityRuleWithMetadata
  extends ISecurityRule, ISecurityRuleMetadata {}
