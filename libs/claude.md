# Libs - Claude Code Context

> **For detailed technical documentation, see [AGENTS.md](./AGENTS.md)**

This file is optimized for Claude Code. Other AI coding agents should reference `AGENTS.md`.

---

## Quick Reference

- **4 Libraries**: core, fuzzer, shared, protocol, transport
- **Core**: 60 security rules, 5 report formats, 3 transports, 4 LLM providers
- **Fuzzer**: 9 generators, 10 detectors, 12 mutation strategies
- **Shared**: i18n, logging, formatters (ZERO dependencies)

**Dependency rules**:
- Domain → shared only (NO frameworks)
- Infrastructure → domain + shared
- Use cases → infrastructure + domain + shared
- Apps → all libs

**Decision guide**:
- Add security rule → `core/domain/security/rules/`
- Add fuzzing generator → `fuzzer/generators/`
- Add report format → `core/domain/reporting/`
- Add utility → `shared/utils/` (if used by 2+ libs)

See [AGENTS.md](./AGENTS.md) for complete architecture, dependency rules, common tasks, and troubleshooting.

---

**Last Updated**: 2026-03-26
