# AI-Assisted Development

## For Developers Using AI Coding Agents

If you're building on top of **MCP Verify** or contributing to the project using AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Codex, etc.), the full AI context files are available in the official repository.

### What you'll find in the repo

| File               | Purpose                                                             |
| ------------------ | ------------------------------------------------------------------- |
| `AGENTS.md`        | Complete technical documentation optimized for all AI coding agents |
| `CLAUDE.md`        | Claude Code-specific context and quick navigation                   |
| `apps/*/AGENTS.md` | Per-app AI context (CLI, MCP Server, VSCode Extension)              |
| `libs/*/AGENTS.md` | Per-library AI context (core, fuzzer, protocol, transport, shared)  |
| `apps/*/CLAUDE.md` | Per-app Claude Code context                                         |
| `libs/*/CLAUDE.md` | Per-library Claude Code context                                     |

These files provide structured context that significantly improves AI agent performance when working with the codebase — architecture overviews, module boundaries, coding conventions, and domain-specific security terminology.

### Get started

```bash
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify
npm install
```

Then open the project with your AI coding agent of choice. The context files are automatically picked up by Claude Code, and can be manually referenced in other agents.

### Why aren't these files in the npm package?

The `AGENTS.md` and `CLAUDE.md` files reference source code, internal file paths, and development workflows that only exist in the cloned repository. Including them in the npm package (which ships only compiled `dist/`) would create confusing references to files that don't exist in the installed package.

---

> **Repository:** https://github.com/FinkTech/mcp-verify
> **Issues & Contributions:** https://github.com/FinkTech/mcp-verify/issues
