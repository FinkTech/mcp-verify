# @mcp-verify/transport — Communication Layer

> **Transition Module**: Moving transport implementations from `core` to this dedicated package.

## 📋 Overview

This library provides the communication bridge between `mcp-verify` and MCP servers. It abstracts the underlying protocols (STDIO, HTTP, SSE) into a unified `ITransport` interface.

### Refactoring Status
- [ ] Move `ITransport` from `@mcp-verify/core`
- [ ] Move `StdioTransport`
- [ ] Move `HttpTransport`
- [ ] Move `SSETransport`

## 📁 Directory Structure

- `base/`: Core interfaces and abstract classes.
- `stdio-client/`: Local process communication logic.
- `http-client/`: Remote REST-based communication.
- `sse-client/`: Real-time streaming communication.

---
*Part of the mcp-verify project.*
