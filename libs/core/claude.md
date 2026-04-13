# @mcp-verify/core - Claude Code Context

> **For detailed technical documentation, see [AGENTS.md](./AGENTS.md)**

This file is optimized for Claude Code. Other AI coding agents should reference `AGENTS.md`.

---

## Quick Reference

- **Clean Architecture**: 3-layer design (Use Cases → Domain → Infrastructure)
- **61 security rules**: OWASP (13) + MCP (8) + LLM Top 10 (9) + Multi-Agent (11) + Compliance (9) + Weaponization (10)
- **5 Report Formats**: HTML, Markdown, SARIF, JSON, Text
- **3 Transports**: stdio, HTTP, SSE
- **4 LLM Providers**: Anthropic, OpenAI, Ollama, Gemini
- **Zero Framework Dependencies**: Domain layer is 100% unit testable

See [AGENTS.md](./AGENTS.md) for complete architecture, security rules catalog, and implementation patterns.

---

**Last Updated**: 2026-03-26

