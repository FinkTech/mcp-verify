/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Workspace Health Check Type Definitions
 *
 * Defines the structure for workspace health status used by the `status` command
 * Includes context info, environment loading, last report, and MCP connection status
 */

/**
 * MCP server connection status
 * Determined via testHandshake() with 2s timeout
 */
export type ConnectionStatus =
  | "connected" // MCP server responded with valid handshake
  | "unreachable" // Network/connection error
  | "protocol_mismatch" // Server responded but not valid MCP protocol
  | "not_configured"; // No target configured

/**
 * Comprehensive workspace health information
 * Displayed by the `status` command
 */
export interface WorkspaceHealth {
  /** Active context information */
  context: {
    /** Context name (e.g., 'dev', 'staging', 'default') */
    name: string;

    /** MCP server target */
    target: string | undefined;

    /** Active security profile name */
    profile: string;
  };

  /** Environment variables status */
  environment: {
    /** Whether .env file was successfully loaded */
    loaded: boolean;

    /** Path to loaded .env file */
    sourceFile: string | undefined;

    /** List of key names that were loaded */
    keysFound: string[];
  };

  /** Last generated report information */
  lastReport: {
    /** Whether a report exists */
    exists: boolean;

    /** Path to the most recent report */
    path: string | undefined;

    /** ISO timestamp when report was generated */
    timestamp: string | undefined;
  };

  /** MCP server connection status */
  connection: {
    /** Connection state */
    status: ConnectionStatus;

    /** Response time in milliseconds (if connected) */
    responseTime?: number;

    /** MCP protocol version (if connected) */
    protocolVersion?: string;

    /** Server name from handshake (if connected) */
    serverName?: string;

    /** Error message (if connection failed) */
    error?: string;
  };
}
