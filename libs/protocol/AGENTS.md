# @mcp-verify/protocol — Agent Context

**Mission**: Single source of truth for MCP protocol schemas and types. Ensuring cross-version compatibility and strict spec adherence.

---

## 🏗️ Refactoring Notice (v1.0)

> **CRITICAL**: This module is currently in **TRANSITION**.
> Types and schemas are currently duplicated or primary in `@mcp-verify/core` to prevent build breakage during refactor.

- **Current Location**: `libs/core/domain/mcp-server/entities/validation.types.ts`
- **Future Home**: This directory (`libs/protocol/v1/`)

---

## 🗺️ Planned Architecture

- **`v1/types/`**: Discriminated unions for JSON-RPC messages.
- **`v1/schemas/`**: Zod and JSON Schema files for runtime validation.
- **`v1/messages/`**: Factory functions for compliant MCP messages.
- **`v-next/`**: Drafts for future MCP versions.

---

## 🛠️ Extension Guide

When adding a new MCP version or message type:
1. Define the interface in `types/`.
2. Add the corresponding JSON Schema in `schemas/`.
3. Export from `v1/index.ts` and then the root `index.ts`.

---

**Last Updated**: 2026-03-31 | Maintainer: @FinkTech via Claude Code
