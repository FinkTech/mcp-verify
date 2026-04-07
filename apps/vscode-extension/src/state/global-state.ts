/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Global State Management
 *
 * Centralized state for the VS Code extension, shared across
 * all views, commands, and providers.
 */

import * as vscode from "vscode";
import {
  Report,
  SecurityFinding,
  DiscoveryResult,
  HandshakeResult,
} from "@mcp-verify/core";

export interface ServerInfo {
  id: string;
  name: string;
  command: string;
  args: string[];
  lastScanned?: Date;
  lastScore?: number;
  status: "idle" | "scanning" | "connected" | "error";
}

export interface ScanResult {
  id: string;
  serverId: string;
  serverName: string;
  timestamp: Date;
  report: Report;
  findings: SecurityFinding[];
  score: number;
  duration: number;
}

export interface ToolInfo {
  name: string;
  description: string;
  serverId: string;
  serverName: string;
  inputSchema?: Record<string, unknown>;
  hasSecurityIssues: boolean;
}

/**
 * Global state singleton for MCP Verify extension
 */
class McpVerifyState {
  private static _instance: McpVerifyState;

  // Event emitters for state changes
  private _onServersChanged = new vscode.EventEmitter<ServerInfo[]>();
  private _onResultsChanged = new vscode.EventEmitter<ScanResult[]>();
  private _onToolsChanged = new vscode.EventEmitter<ToolInfo[]>();
  private _onHistoryChanged = new vscode.EventEmitter<ScanResult[]>();
  private _onActiveServerChanged = new vscode.EventEmitter<
    ServerInfo | undefined
  >();

  // Public events
  readonly onServersChanged = this._onServersChanged.event;
  readonly onResultsChanged = this._onResultsChanged.event;
  readonly onToolsChanged = this._onToolsChanged.event;
  readonly onHistoryChanged = this._onHistoryChanged.event;
  readonly onActiveServerChanged = this._onActiveServerChanged.event;

  // State
  private _servers: Map<string, ServerInfo> = new Map();
  private _results: Map<string, ScanResult> = new Map();
  private _tools: Map<string, ToolInfo> = new Map();
  private _history: ScanResult[] = [];
  private _activeServer?: ServerInfo;
  private _context?: vscode.ExtensionContext;

  private constructor() {}

  static getInstance(): McpVerifyState {
    if (!McpVerifyState._instance) {
      McpVerifyState._instance = new McpVerifyState();
    }
    return McpVerifyState._instance;
  }

  /**
   * Initialize state with extension context
   */
  initialize(context: vscode.ExtensionContext): void {
    this._context = context;
    this.loadPersistedState();
  }

  /**
   * Load persisted state from workspace storage
   */
  private loadPersistedState(): void {
    if (!this._context) return;

    // Load recent servers
    const servers = this._context.workspaceState.get<ServerInfo[]>(
      "mcp-verify.servers",
      [],
    );
    servers.forEach((s) => this._servers.set(s.id, s));

    // Load scan history
    const history = this._context.workspaceState.get<ScanResult[]>(
      "mcp-verify.history",
      [],
    );
    this._history = history.map((h) => ({
      ...h,
      timestamp: new Date(h.timestamp),
    }));
  }

  /**
   * Persist state to workspace storage
   */
  private persistState(): void {
    if (!this._context) return;

    this._context.workspaceState.update(
      "mcp-verify.servers",
      Array.from(this._servers.values()),
    );
    this._context.workspaceState.update(
      "mcp-verify.history",
      this._history.slice(0, 50),
    ); // Keep last 50
  }

  // === Server Management ===

  getServers(): ServerInfo[] {
    return Array.from(this._servers.values());
  }

  getServer(id: string): ServerInfo | undefined {
    return this._servers.get(id);
  }

  addServer(server: Omit<ServerInfo, "id">): ServerInfo {
    const id = `server-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newServer: ServerInfo = { ...server, id };
    this._servers.set(id, newServer);
    this._onServersChanged.fire(this.getServers());
    this.persistState();
    return newServer;
  }

  updateServer(id: string, updates: Partial<ServerInfo>): void {
    const server = this._servers.get(id);
    if (server) {
      Object.assign(server, updates);
      this._onServersChanged.fire(this.getServers());
      this.persistState();
    }
  }

  removeServer(id: string): void {
    this._servers.delete(id);
    this._onServersChanged.fire(this.getServers());
    this.persistState();
  }

  setActiveServer(server: ServerInfo | undefined): void {
    this._activeServer = server;
    this._onActiveServerChanged.fire(server);
  }

  getActiveServer(): ServerInfo | undefined {
    return this._activeServer;
  }

  // === Results Management ===

  getResults(): ScanResult[] {
    return Array.from(this._results.values());
  }

  getLatestResult(): ScanResult | undefined {
    const results = this.getResults();
    return results.sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime(),
    )[0];
  }

  addResult(result: Omit<ScanResult, "id">): ScanResult {
    const id = `result-${Date.now()}`;
    const newResult: ScanResult = { ...result, id };
    this._results.set(id, newResult);

    // Also add to history
    this._history.unshift(newResult);
    if (this._history.length > 50) {
      this._history = this._history.slice(0, 50);
    }

    this._onResultsChanged.fire(this.getResults());
    this._onHistoryChanged.fire(this._history);
    this.persistState();

    return newResult;
  }

  clearResults(): void {
    this._results.clear();
    this._onResultsChanged.fire([]);
  }

  // === Tools Management ===

  getTools(): ToolInfo[] {
    return Array.from(this._tools.values());
  }

  setTools(tools: ToolInfo[]): void {
    this._tools.clear();
    tools.forEach((t) => this._tools.set(`${t.serverId}:${t.name}`, t));
    this._onToolsChanged.fire(this.getTools());
  }

  clearTools(): void {
    this._tools.clear();
    this._onToolsChanged.fire([]);
  }

  // === History Management ===

  getHistory(): ScanResult[] {
    return [...this._history];
  }

  clearHistory(): void {
    this._history = [];
    this._onHistoryChanged.fire([]);
    this.persistState();
  }

  // === Utility ===

  dispose(): void {
    this._onServersChanged.dispose();
    this._onResultsChanged.dispose();
    this._onToolsChanged.dispose();
    this._onHistoryChanged.dispose();
    this._onActiveServerChanged.dispose();
  }
}

// Export singleton instance
export const globalState = McpVerifyState.getInstance();
