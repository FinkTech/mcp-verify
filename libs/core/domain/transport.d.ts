/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { ISandbox } from './sandbox/sandbox.interface';
import { JsonValue, JsonRpcRequest } from './shared/common.types';
export interface TransportOptions {
    timeoutMs?: number;
}
export interface ITransport {
    connect(): Promise<void>;
    send(message: JsonRpcRequest, options?: TransportOptions): Promise<JsonValue>;
    close(): void;
}
export declare class HttpTransport implements ITransport {
    private url;
    private defaultTimeout;
    constructor(url: string, defaultTimeout?: number);
    connect(): Promise<void>;
    send(message: JsonRpcRequest, options?: TransportOptions): Promise<JsonValue>;
    close(): void;
}
export declare class StdioTransport implements ITransport {
    private static readonly MAX_BUFFER_SIZE;
    private command;
    private args;
    private process;
    private buffer;
    private decoder;
    private pendingRequests;
    private defaultTimeout;
    private env;
    private sandbox?;
    private stderrBuffer;
    private static readonly MAX_STDERR_LINES;
    constructor(command: string, args?: string[], defaultTimeout?: number, env?: NodeJS.ProcessEnv, sandbox?: ISandbox);
    connect(): Promise<void>;
    private handleData;
    send(message: JsonRpcRequest, options?: TransportOptions): Promise<JsonValue>;
    close(): void;
}
//# sourceMappingURL=transport.d.ts.map