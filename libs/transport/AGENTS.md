# @mcp-verify/transport — Agent Context

**Mission**: Unified communication layer for MCP protocols. Abstracting STDIO, HTTP, and SSE into a single interface.

---

## 🏗️ Refactoring Notice (v1.0)

> **CRITICAL**: This module is currently in **TRANSITION**.
> Most logic still resides in `@mcp-verify/core` to maintain stability during initial v1.0 release.

- **Current Location**: `libs/core/domain/transport.ts`
- **Future Home**: This directory (`libs/transport/`)

---

## 🗺️ Planned Architecture

- **`base/`**: `ITransport` interface and common error handlers.
- **`stdio-client/`**: `StdioTransport` (spawn, stdin/stdout management).
- **`http-client/`**: `HttpTransport` (fetch with custom User-Agent).
- **`sse-client/`**: `SSETransport` (EventSource integration).

---

## 🛠️ Extension Guide

When moving a transport here:

1. Copy implementation from `core`.
2. Update imports to use `@mcp-verify/shared` for utilities (User-Agent, Logger).
3. Export from `index.ts`.
4. Update `core` to import from this package.

---

**Last Updated**: 2026-04-08 | Maintainer: @FinkTech via Claude Code
