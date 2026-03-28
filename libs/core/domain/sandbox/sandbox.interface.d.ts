/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export interface SandboxOptions {
    allowRead?: string[];
    allowNet?: string[];
    allowEnv?: boolean;
}
export interface ISandbox {
    /**
     * Envelops a command and its arguments into a sandboxed execution.
     * @returns A tuple of [sandboxedCommand, sandboxedArgs[]]
     */
    wrap(command: string, args: string[]): [string, string[]];
}
//# sourceMappingURL=sandbox.interface.d.ts.map