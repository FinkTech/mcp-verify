/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Scan History Tree View
 *
 * Displays past scan results with timestamps and scores.
 */

import * as vscode from 'vscode';
import { globalState, ScanResult } from '../state/global-state';

interface HistoryGroup {
    type: 'date';
    label: string;
    date: string;
    results: ScanResult[];
}

type HistoryTreeItem = HistoryGroup | ScanResult;

export class HistoryTreeProvider implements vscode.TreeDataProvider<HistoryTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<HistoryTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor() {
        globalState.onHistoryChanged(() => this.refresh());
    }

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: HistoryTreeItem): vscode.TreeItem {
        if ('type' in element && element.type === 'date') {
            // Date group
            const item = new vscode.TreeItem(element.label);
            item.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
            item.iconPath = new vscode.ThemeIcon('calendar');
            item.description = `${element.results.length} scan${element.results.length !== 1 ? 's' : ''}`;
            item.contextValue = 'date-group';
            return item;
        }

        // Scan result
        const result = element as ScanResult;
        const item = new vscode.TreeItem(result.serverName);
        item.description = `Score: ${result.score} | ${this.formatTime(result.timestamp)}`;
        item.iconPath = this.getScoreIcon(result.score);
        item.tooltip = this.createTooltip(result);
        item.contextValue = 'scan-result';
        item.command = {
            command: 'mcp-verify.showHistoryReport',
            title: 'Show Report',
            arguments: [result]
        };
        return item;
    }

    getChildren(element?: HistoryTreeItem): HistoryTreeItem[] {
        if (!element) {
            // Root - group by date
            const history = globalState.getHistory();

            if (history.length === 0) {
                return [];
            }

            const groups = new Map<string, ScanResult[]>();

            history.forEach(result => {
                const date = new Date(result.timestamp);
                const dateKey = date.toDateString();
                const list = groups.get(dateKey) || [];
                list.push(result);
                groups.set(dateKey, list);
            });

            return Array.from(groups.entries()).map(([dateKey, results]) => ({
                type: 'date' as const,
                label: this.formatDateLabel(dateKey),
                date: dateKey,
                results: results.sort((a, b) =>
                    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                )
            }));
        }

        // Date group children
        if ('type' in element && element.type === 'date') {
            return element.results;
        }

        return [];
    }

    private formatDateLabel(dateString: string): string {
        const date = new Date(dateString);
        const today = new Date();
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);

        if (date.toDateString() === today.toDateString()) {
            return 'Today';
        } else if (date.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        } else {
            return date.toLocaleDateString(undefined, {
                weekday: 'long',
                month: 'short',
                day: 'numeric'
            });
        }
    }

    private formatTime(timestamp: Date): string {
        return new Date(timestamp).toLocaleTimeString(undefined, {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    private getScoreIcon(score: number): vscode.ThemeIcon {
        if (score >= 90) {
            return new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.green'));
        } else if (score >= 70) {
            return new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.yellow'));
        } else if (score >= 50) {
            return new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.orange'));
        } else {
            return new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.red'));
        }
    }

    private createTooltip(result: ScanResult): vscode.MarkdownString {
        const md = new vscode.MarkdownString();
        md.appendMarkdown(`**${result.serverName}**\n\n`);
        md.appendMarkdown(`**Score:** ${result.score}/100\n\n`);
        md.appendMarkdown(`**Time:** ${new Date(result.timestamp).toLocaleString()}\n\n`);
        md.appendMarkdown(`**Duration:** ${result.duration}ms\n\n`);
        md.appendMarkdown(`**Findings:** ${result.findings.length}\n\n`);

        // Breakdown by severity
        const severityCounts = result.findings.reduce((acc, f) => {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        if (Object.keys(severityCounts).length > 0) {
            md.appendMarkdown('**Breakdown:**\n');
            Object.entries(severityCounts).forEach(([sev, count]) => {
                md.appendMarkdown(`- ${sev}: ${count}\n`);
            });
        }

        md.isTrusted = true;
        return md;
    }
}
