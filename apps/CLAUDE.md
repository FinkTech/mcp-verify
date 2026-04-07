# Apps - Claude Code Context

> **For detailed technical documentation, see [AGENTS.md](./AGENTS.md)**

This file is optimized for Claude Code. Other AI coding agents should reference `AGENTS.md`.

---

## Quick Reference

- **3 Apps**: CLI Verifier, MCP Server, VS Code Extension
- **CLI**: Interactive shell with multi-context workspace, 13 commands
- **MCP Server**: 7 tools for AI agents (validateServer, scanSecurity, etc.)
- **VSCode Extension**: Real-time diagnostics, code actions, 4 tree views

**Decision guide**:

- Add CLI command → `cli-verifier/src/commands/`
- Add MCP tool → `mcp-server/src/tools/`
- Add VSCode command → `vscode-extension/src/commands/`
- Add security rule → `libs/core/domain/security/rules/` (not apps)

See [AGENTS.md](./AGENTS.md) for complete app architecture, build commands, integration patterns, and troubleshooting.

---

**Last Updated**: 2026-03-26
