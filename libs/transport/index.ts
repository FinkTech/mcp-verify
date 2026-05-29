/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * @finktech/transport
 *
 * Transport layer implementations for MCP communication.
 * Supports STDIO, SSE, and HTTP transports.
 *
 * NOTE: Transport implementations are currently in @finktech/core.
 * This package will be populated during the refactoring phase.
 *
 * @example
 * ```typescript
 * import { StdioTransport, SSETransport } from '@finktech/transport';
 * ```
 */

// TODO: Move transports from libs/core/domain/transport.ts here
// export * from './base/transport.interface';
// export * from './stdio-client/stdio-transport';
// export * from './sse-client/sse-transport';
// export * from './http-client/http-transport';

export const TRANSPORT_VERSION = "1.0.0";
