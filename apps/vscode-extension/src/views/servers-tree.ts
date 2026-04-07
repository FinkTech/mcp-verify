/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Servers Tree View
 *
 * Displays configured MCP servers and their status.
 */

import * as vscode from "vscode";
import { globalState, ServerInfo } from "../state/global-state";

export class ServersTreeProvider implements vscode.TreeDataProvider<ServerInfo> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    ServerInfo | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor() {
    globalState.onServersChanged(() => this.refresh());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: ServerInfo): vscode.TreeItem {
    const item = new vscode.TreeItem(element.name);
    item.description = this.getStatusDescription(element);
    item.iconPath = this.getStatusIcon(element);
    item.tooltip = this.createTooltip(element);
    item.contextValue = `server-${element.status}`;
    item.command = {
      command: "mcp-verify.selectServer",
      title: "Select Server",
      arguments: [element],
    };
    return item;
  }

  getChildren(): ServerInfo[] {
    return globalState.getServers();
  }

  private getStatusDescription(server: ServerInfo): string {
    const parts: string[] = [];

    if (server.lastScore !== undefined) {
      parts.push(`Score: ${server.lastScore}`);
    }

    if (server.lastScanned) {
      const date = new Date(server.lastScanned);
      parts.push(date.toLocaleDateString());
    }

    return parts.join(" | ");
  }

  private getStatusIcon(server: ServerInfo): vscode.ThemeIcon {
    switch (server.status) {
      case "scanning":
        return new vscode.ThemeIcon(
          "sync~spin",
          new vscode.ThemeColor("charts.blue"),
        );
      case "connected":
        return new vscode.ThemeIcon(
          "vm-running",
          new vscode.ThemeColor("charts.green"),
        );
      case "error":
        return new vscode.ThemeIcon(
          "error",
          new vscode.ThemeColor("errorForeground"),
        );
      case "idle":
      default:
        return new vscode.ThemeIcon("server");
    }
  }

  private createTooltip(server: ServerInfo): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${server.name}**\n\n`);
    md.appendMarkdown(`**Command:** \`${server.command}\`\n\n`);
    if (server.args.length > 0) {
      md.appendMarkdown(`**Args:** \`${server.args.join(" ")}\`\n\n`);
    }
    md.appendMarkdown(`**Status:** ${server.status}\n\n`);
    if (server.lastScore !== undefined) {
      md.appendMarkdown(`**Last Score:** ${server.lastScore}/100\n\n`);
    }
    if (server.lastScanned) {
      md.appendMarkdown(
        `**Last Scan:** ${new Date(server.lastScanned).toLocaleString()}\n\n`,
      );
    }
    md.isTrusted = true;
    return md;
  }
}
