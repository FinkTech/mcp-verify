/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fuzzer Utilities
 *
 * Helper functions for report generation, mapping, and integration.
 */

export {
  // Mapper functions
  sessionToFuzzingReport,
  sessionToSecurityFindings,
  sessionToReport,
  sessionToSummary,
  // Types
  ReportMapperOptions,
  FuzzerSecurityFinding,
  FuzzingSummary,
} from "./report-mapper";
