# Smart Fuzzer Engine - Claude Code Context

> **For detailed technical documentation, see [AGENTS.md](./AGENTS.md)**

This file is optimized for Claude Code. Other AI coding agents should reference `AGENTS.md`.

---

## Quick Reference

- **9 Generators**: Prompt injection, JWT, SQL/XSS, schema confusion, prototype pollution
- **10 Detectors**: Timing, error, XSS, prompt leak, jailbreak, path traversal
- **12 Mutation Strategies**: Bit flip, encoding, case, repeat, nesting, boundary testing
- **Feedback Loop**: Baseline → Execute → Detect anomalies → Mutate → Repeat (max 3 rounds)

See [AGENTS.md](./AGENTS.md) for complete fuzzer architecture, generator/detector implementation patterns, and troubleshooting guide.

---

**Last Updated**: 2026-03-26
