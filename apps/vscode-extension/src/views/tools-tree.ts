/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Tools Tree View
 *
 * Displays discovered tools from MCP servers.
 */

import * as vscode from 'vscode';
import { globalState, ToolInfo } from '../state/global-state';

type ToolTreeItem = ToolInfo | { type: 'server'; name: string; tools: ToolInfo[] };

export class ToolsTreeProvider implements vscode.TreeDataProvider<ToolTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<ToolTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor() {
        globalState.onToolsChanged(() => this.refresh());
    }

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: ToolTreeItem): vscode.TreeItem {
        if ('type' in element && element.type === 'server') {
            // Server group
            const item = new vscode.TreeItem(element.name);
            item.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
            item.iconPath = new vscode.ThemeIcon('server');
            item.description = `${element.tools.length} tool${element.tools.length !== 1 ? 's' : ''}`;
            item.contextValue = 'server-group';
            return item;
        }

        // Tool item
        const tool = element as ToolInfo;
        const item = new vscode.TreeItem(tool.name);
        item.description = tool.description.substring(0, 50) + (tool.description.length > 50 ? '...' : '');
        item.iconPath = tool.hasSecurityIssues
            ? new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'))
            : new vscode.ThemeIcon('symbol-function');
        item.tooltip = this.createTooltip(tool);
        item.contextValue = tool.hasSecurityIssues ? 'tool-vulnerable' : 'tool';
        item.command = {
            command: 'mcp-verify.executeTool',
            title: 'Execute Tool',
            arguments: [tool]
        };
        return item;
    }

    getChildren(element?: ToolTreeItem): ToolTreeItem[] {
        if (!element) {
            // Root - group by server
            const tools = globalState.getTools();
            const serverGroups = new Map<string, ToolInfo[]>();

            tools.forEach(tool => {
                const key = tool.serverName;
                const list = serverGroups.get(key) || [];
                list.push(tool);
                serverGroups.set(key, list);
            });

            if (serverGroups.size === 0) {
                return [];
            }

            // If only one server, show tools directly
            if (serverGroups.size === 1) {
                const [, tools] = Array.from(serverGroups.entries())[0];
                return tools;
            }

            // Multiple servers - show groups
            return Array.from(serverGroups.entries()).map(([name, tools]) => ({
                type: 'server' as const,
                name,
                tools
            }));
        }

        // Server group children
        if ('type' in element && element.type === 'server') {
            return element.tools;
        }

        return [];
    }

    private createTooltip(tool: ToolInfo): vscode.MarkdownString {
        const md = new vscode.MarkdownString();
        md.appendMarkdown(`**${tool.name}**\n\n`);
        md.appendMarkdown(`${tool.description}\n\n`);
        md.appendMarkdown(`**Server:** ${tool.serverName}\n\n`);

        if (tool.inputSchema) {
            md.appendMarkdown(`**Input Schema:**\n\`\`\`json\n${JSON.stringify(tool.inputSchema, null, 2)}\n\`\`\`\n\n`);
        }

        if (tool.hasSecurityIssues) {
            md.appendMarkdown(`\n\n$(warning) **This tool has security issues**`);
        }

        md.isTrusted = true;
        return md;
    }
}
