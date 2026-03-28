/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-045: Insufficient Error Granularity
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Fuzzer (requires runtime testing)
 *
 * Detects errors that are either:
 * (a) Too verbose - exposing stack traces, paths, versions
 * (b) Too generic - only error codes without messages
 *
 * Both extremes are problematic for agents making decisions based on errors.
 *
 * Detection:
 * - Requires fuzzer to send malformed inputs and analyze error responses
 * - This is a PLACEHOLDER for static analysis
 *
 * References:
 * - OWASP Error Handling Cheat Sheet
 * - CWE-209: Information Exposure Through Error Messages
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';

export class InsufficientErrorGranularityRule implements ISecurityRule {
  code = 'SEC-045';
  name = 'Insufficient Error Granularity';
  severity: 'medium' = 'medium';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    // This rule requires fuzzer execution to test error responses
    // Static analysis cannot detect error message quality
    return [];
  }
}
