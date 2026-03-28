/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Workspace Health Checker
 *
 * Performs comprehensive health checks on the current workspace:
 * - Context information (active context, target, profile)
 * - Environment variables (loaded from .env)
 * - Last generated report
 * - MCP server connection (via real protocol handshake)
 */

import fs from 'fs';
import path from 'path';
import { WorkspaceHealth, ConnectionStatus } from '../types/workspace-health';
import { EnvironmentVars } from '../types/environment-vars';
import { WorkspaceContext } from '../types/workspace-context';
import { EnvironmentLoader } from './environment-loader';
import { createTransport } from '../../utils/transport-factory';
import { MCPValidator } from '@mcp-verify/core/use-cases/validator/validator';
import { HandshakeResult } from '@mcp-verify/core/domain/mcp-server/entities/validation.types';
import { Logger } from '@mcp-verify/core/infrastructure/logging/logger';

/**
 * Workspace health checker
 * Provides comprehensive status information for the `status` command
 */
export class WorkspaceHealthChecker {
  /** Timeout for MCP handshake test (2 seconds) */
  private static readonly HEALTH_TIMEOUT = 2000;

  /** Paths where reports are typically stored */
  private static readonly REPORT_PATHS = [
    'reports/html',
    'reports/json',
    'reports/md',
  ];

  /**
   * Perform comprehensive workspace health check
   *
   * @param activeContextName - Name of the active context
   * @param activeContext - Active context data
   * @param environment - Environment variables (or undefined if not loaded)
   * @returns WorkspaceHealth object with all health information
   */
  static async check(
    activeContextName: string,
    activeContext: WorkspaceContext,
    environment: EnvironmentVars | undefined
  ): Promise<WorkspaceHealth> {
    // Load environment if not provided
    const env = environment ?? EnvironmentLoader.load();

    return {
      context: {
        name: activeContextName,
        target: activeContext.target,
        profile: activeContext.profile.name,
      },
      environment: {
        loaded: env.sourceFile !== undefined,
        sourceFile: env.sourceFile,
        keysFound: EnvironmentLoader.getLoadedKeys(env),
      },
      lastReport: WorkspaceHealthChecker.checkLastReport(),
      connection: await WorkspaceHealthChecker.checkConnection(activeContext.target),
    };
  }

  /**
   * TIMEOUT-SAFE: Check MCP server connection using real protocol handshake
   * Uses strict Promise.race with 2s timeout - NEVER blocks the shell
   *
   * @param target - MCP server target (command, URL, or undefined)
   * @returns Connection status information
   */
  private static async checkConnection(
    target: string | undefined
  ): Promise<WorkspaceHealth['connection']> {
    if (!target) {
      return {
        status: 'not_configured',
      };
    }

    const startTime = Date.now();
    let transport: ReturnType<typeof createTransport> | undefined;

    try {
      // Create transport with same timeout as health check
      transport = createTransport(target, {
        timeout: WorkspaceHealthChecker.HEALTH_TIMEOUT,
      });

      // Create validator (uses default scoped logger internally)
      const validator = new MCPValidator(transport);

      // CRITICAL: Strict timeout with Promise.race
      // This guarantees we NEVER wait more than HEALTH_TIMEOUT milliseconds
      const handshakePromise = WorkspaceHealthChecker.performHandshake(validator);
      const timeoutPromise = new Promise<HandshakeResult>((resolve) => {
        setTimeout(() => {
          resolve({
            success: false,
            error: 'Connection timeout (2000ms exceeded)',
          });
        }, WorkspaceHealthChecker.HEALTH_TIMEOUT);
      });

      const result = await Promise.race([handshakePromise, timeoutPromise]);
      const responseTime = Date.now() - startTime;

      // Map HandshakeResult to ConnectionStatus
      if (result.success) {
        return {
          status: 'connected',
          responseTime,
          protocolVersion: result.protocolVersion,
          serverName: result.serverName,
        };
      }

      // Check if error indicates protocol mismatch
      const errorMsg = result.error ?? '';
      if (
        errorMsg.includes('protocol') ||
        errorMsg.includes('invalid') ||
        errorMsg.includes('version')
      ) {
        return {
          status: 'protocol_mismatch',
          responseTime,
          error: errorMsg,
        };
      }

      // Connection failed or timeout
      return {
        status: 'unreachable',
        responseTime,
        error: errorMsg,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        status: 'unreachable',
        responseTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    } finally {
      // CRITICAL: Always close transport to prevent resource leaks
      if (transport) {
        try {
          await transport.close();
        } catch {
          // Ignore close errors - we're already returning
        }
      }
    }
  }

  /**
   * Perform MCP handshake test
   *
   * @param validator - MCPValidator instance
   * @returns HandshakeResult with connection status
   */
  private static async performHandshake(
    validator: MCPValidator
  ): Promise<HandshakeResult> {
    try {
      return await validator.testHandshake();
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Handshake failed',
      };
    }
  }

  /**
   * Find the most recent report in the reports directory
   *
   * @returns Last report information
   */
  private static checkLastReport(): WorkspaceHealth['lastReport'] {
    try {
      let mostRecent: { path: string; timestamp: string } | undefined;

      // Search all report directories
      for (const reportDir of WorkspaceHealthChecker.REPORT_PATHS) {
        const fullPath = path.join(process.cwd(), reportDir);

        if (!fs.existsSync(fullPath)) {
          continue;
        }

        // Find all report files
        const files = fs.readdirSync(fullPath);
        for (const file of files) {
          const filePath = path.join(fullPath, file);
          const stats = fs.statSync(filePath);

          if (!stats.isFile()) {
            continue;
          }

          // Use file modification time as timestamp
          const timestamp = stats.mtime.toISOString();

          if (!mostRecent || timestamp > mostRecent.timestamp) {
            mostRecent = {
              path: path.join(reportDir, file),
              timestamp,
            };
          }
        }
      }

      if (mostRecent) {
        return {
          exists: true,
          path: mostRecent.path,
          timestamp: mostRecent.timestamp,
        };
      }

      return {
        exists: false,
        path: undefined,
        timestamp: undefined,
      };
    } catch {
      // Error reading reports directory
      return {
        exists: false,
        path: undefined,
        timestamp: undefined,
      };
    }
  }
}
