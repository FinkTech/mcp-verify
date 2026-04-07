# @mcp-verify/protocol — MCP Specification & Types

> **Transition Module**: Consolidating Model Context Protocol (MCP) definitions, JSON schemas, and TypeScript types.

## 📋 Overview

This library serves as the single source of truth for MCP protocol compliance. It contains the official message schemas, type guards, and protocol versioning used by `mcp-verify`.

### Refactoring Status

- [ ] Move MCP JSON Schemas from `core/domain/mcp-server/`
- [ ] Move TypeScript interfaces
- [ ] Implement version-specific validation (v1 vs v-next)

## 📁 Directory Structure

- `v1/`: Stable MCP specification types and schemas.
  - `messages/`: Request/Response/Notification shapes.
  - `schemas/`: JSON Schema definitions for validation.
  - `types/`: Pure TypeScript interfaces.
- `v-next/`: Emerging specification features for future-proofing.

---

_Part of the mcp-verify project._
