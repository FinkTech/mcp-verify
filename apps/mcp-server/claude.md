# MCP Server - Claude Code Context

> **For detailed technical documentation, see [AGENTS.md](./AGENTS.md)**

This file is optimized for Claude Code. Other AI coding agents should reference `AGENTS.md`.

---

- **7 MCP Tools**: validateServer, scanSecurity, analyzeQuality, generateReport, listInstalledServers, selfAudit, compareServers
- **LLM-Optimized**: formatForLLM() transforms reports for AI agent consumption
- **Auto-Discovery**: Finds MCP servers from Claude Desktop, Gemini CLI, Cursor, Zed configs
- **First-of-its-kind**: AI agents validating other MCP servers via MCP protocol

See [AGENTS.md](./AGENTS.md) for complete tool specs, LLM formatting strategy, and integration details.

---

**Last Updated**: 2026-03-26
