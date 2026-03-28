/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Security Results Tree View
 *
 * Displays security findings in a hierarchical tree structure,
 * grouped by severity and rule.
 */

import * as vscode from 'vscode';
import { SecurityFinding, Severity } from '@mcp-verify/core';
import { globalState, ScanResult } from '../state/global-state';

type TreeItemType = 'severity' | 'rule' | 'finding' | 'empty';

interface FindingTreeItem {
    type: TreeItemType;
    label: string;
    severity?: Severity;
    ruleCode?: string;
    finding?: SecurityFinding;
    children?: FindingTreeItem[];
    count?: number;
}

export class ResultsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private findings: SecurityFinding[] = [];
    private score: number = 0;

    constructor() {
        // Listen to state changes
        globalState.onResultsChanged(() => this.refresh());
    }

    refresh(): void {
        const latest = globalState.getLatestResult();
        if (latest) {
            this.findings = latest.findings;
            this.score = latest.score;
        } else {
            this.findings = [];
            this.score = 0;
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    setFindings(findings: SecurityFinding[], score: number): void {
        this.findings = findings;
        this.score = score;
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: FindingTreeItem): vscode.TreeItem {
        const item = new vscode.TreeItem(element.label);

        switch (element.type) {
            case 'severity':
                item.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
                item.iconPath = this.getSeverityIcon(element.severity!);
                item.description = `${element.count} issue${element.count !== 1 ? 's' : ''}`;
                item.contextValue = 'severity';
                break;

            case 'rule':
                item.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
                item.iconPath = new vscode.ThemeIcon('warning');
                item.description = element.ruleCode;
                item.contextValue = 'rule';
                break;

            case 'finding':
                item.collapsibleState = vscode.TreeItemCollapsibleState.None;
                item.iconPath = this.getSeverityIcon(element.finding!.severity);
                item.tooltip = this.createFindingTooltip(element.finding!);
                item.command = {
                    command: 'mcp-verify.showFindingDetails',
                    title: 'Show Details',
                    arguments: [element.finding]
                };
                item.contextValue = 'finding';
                break;

            case 'empty':
                item.collapsibleState = vscode.TreeItemCollapsibleState.None;
                item.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.green'));
                item.contextValue = 'empty';
                break;
        }

        return item;
    }

    getChildren(element?: FindingTreeItem): FindingTreeItem[] {
        if (!element) {
            // Root level - show severity groups or empty message
            if (this.findings.length === 0) {
                return [{
                    type: 'empty',
                    label: `No security issues found (Score: ${this.score}/100)`
                }];
            }

            return this.groupBySeverity();
        }

        // Return children
        return element.children || [];
    }

    private groupBySeverity(): FindingTreeItem[] {
        const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
        const groups = new Map<Severity, SecurityFinding[]>();

        // Initialize groups
        severityOrder.forEach(s => groups.set(s, []));

        // Group findings
        this.findings.forEach(f => {
            const list = groups.get(f.severity) || [];
            list.push(f);
            groups.set(f.severity, list);
        });

        // Build tree items
        const items: FindingTreeItem[] = [];

        severityOrder.forEach(severity => {
            const findings = groups.get(severity) || [];
            if (findings.length === 0) return;

            // Group by rule within severity
            const ruleGroups = new Map<string, SecurityFinding[]>();
            findings.forEach(f => {
                const ruleKey = f.ruleCode || 'UNKNOWN';
                const list = ruleGroups.get(ruleKey) || [];
                list.push(f);
                ruleGroups.set(ruleKey, list);
            });

            const ruleItems: FindingTreeItem[] = [];
            ruleGroups.forEach((ruleFindings, ruleCode) => {
                const findingItems: FindingTreeItem[] = ruleFindings.map(f => ({
                    type: 'finding' as const,
                    label: f.message.substring(0, 60) + (f.message.length > 60 ? '...' : ''),
                    finding: f
                }));

                ruleItems.push({
                    type: 'rule',
                    label: ruleFindings[0].ruleName || ruleCode,
                    ruleCode,
                    children: findingItems,
                    count: findingItems.length
                });
            });

            items.push({
                type: 'severity',
                label: this.formatSeverity(severity),
                severity,
                children: ruleItems,
                count: findings.length
            });
        });

        return items;
    }

    private getSeverityIcon(severity: Severity): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'low':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case 'info':
                return new vscode.ThemeIcon('info');
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }

    private formatSeverity(severity: Severity): string {
        return severity.charAt(0).toUpperCase() + severity.slice(1);
    }

    private createFindingTooltip(finding: SecurityFinding): vscode.MarkdownString {
        const md = new vscode.MarkdownString();
        md.appendMarkdown(`**${finding.ruleCode}: ${finding.ruleName}**\n\n`);
        md.appendMarkdown(`${finding.message}\n\n`);
        md.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
        if (finding.remediation) {
            md.appendMarkdown(`**Remediation:** ${finding.remediation}\n\n`);
        }
        if (finding.toolName) {
            md.appendMarkdown(`**Tool:** ${finding.toolName}\n\n`);
        }
        md.isTrusted = true;
        return md;
    }
}
