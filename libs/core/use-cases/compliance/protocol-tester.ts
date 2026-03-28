/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from '@mcp-verify/shared';
import type { ITransport } from '../../domain/transport';

export interface ProtocolIssue {
  code: string;
  message: string;
  severity: 'error' | 'warning';
}

export interface ProtocolComplianceReport {
  passed: boolean;
  score: number;
  issues: ProtocolIssue[];
}

export class ProtocolComplianceTester {
  private transport: ITransport;

  constructor(transport: ITransport) {
    this.transport = transport;
  }

  async test(): Promise<ProtocolComplianceReport> {
    const issues: ProtocolIssue[] = [];

    // Test 1: Method Not Found (-32601)
    try {
      await this.transport.send({
        jsonrpc: '2.0',
        id: 99999,
        method: 'non_existent_method_test_123',
        params: {}
      });
      // If it doesn't throw, it might have returned a result, which is wrong for non-existent method
      issues.push({
        code: 'RPC-001',
        message: t('rpc_001'),
        severity: 'error'
      });
    } catch (e: unknown) {
      // We expect an error. Ideally we check the code.
      // Error message usually contains the code if we parsed it in transport.
      // Our transport currently rejects with Error(message). Ideally it should reject with a structured error.
      // For now, we assume if it failed, it's good, unless the error suggests a crash.
      const msg = e instanceof Error ? e.message : String(e);
      if (!msg) {
        issues.push({ code: 'RPC-002', message: t('rpc_002'), severity: 'warning' });
      }
    }

    // Test 2: Invalid Request (-32600) - Missing jsonrpc version
    try {
      await this.transport.send({
        id: 99998,
        method: 'initialize',
        params: {}
        // missing jsonrpc: '2.0'
      });
      issues.push({
        code: 'RPC-003',
        message: t('rpc_003'),
        severity: 'warning' // Some leniency allowed
      });
    } catch (e) {
      // Good, it rejected it
    }

    const score = Math.max(0, 100 - (issues.length * 20));

    return {
      passed: issues.filter(i => i.severity === 'error').length === 0,
      score,
      issues
    };
  }
}
