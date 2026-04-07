/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Output Channel Logger
 */

import * as vscode from "vscode";

export class OutputChannelLogger {
  private channel: vscode.OutputChannel;

  constructor(name: string) {
    this.channel = vscode.window.createOutputChannel(name);
  }

  private timestamp(): string {
    return new Date().toLocaleTimeString();
  }

  info(message: string): void {
    this.channel.appendLine(`[${this.timestamp()}] INFO: ${message}`);
  }

  success(message: string): void {
    this.channel.appendLine(`[${this.timestamp()}] OK: ${message}`);
  }

  warn(message: string): void {
    this.channel.appendLine(`[${this.timestamp()}] WARN: ${message}`);
  }

  error(message: string, error?: unknown): void {
    this.channel.appendLine(`[${this.timestamp()}] ERROR: ${message}`);
    if (error instanceof Error) {
      this.channel.appendLine(`  ${error.message}`);
      if (error.stack) {
        this.channel.appendLine(`  Stack: ${error.stack}`);
      }
    }
  }

  show(): void {
    this.channel.show();
  }

  dispose(): void {
    this.channel.dispose();
  }

  getChannel(): vscode.OutputChannel {
    return this.channel;
  }
}
