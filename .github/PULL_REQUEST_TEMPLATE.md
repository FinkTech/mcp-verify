## Description

<!-- Describe what this PR does in 2-3 sentences -->

## Type of Change

<!-- Mark with 'x' what applies -->

- [ ] 🎉 New feature (adds new functionality)
- [ ] 🐛 Bug fix (fixes an issue)
- [ ] 🔧 Refactor (code change that doesn't add features or fix bugs)
- [ ] 📚 Documentation (documentation-only changes)
- [ ] ✅ Tests (adding or fixing tests)
- [ ] 🔒 Security (vulnerability fix or security improvement)
- [ ] ⚡ Performance (performance improvement)

## Code Standards Checklist

<!-- ALL items must be checked before merging -->

- [ ] Followed [`AGENTS.md`](../AGENTS.md) rules
- [ ] **Zero `any`**: Didn't use `any`, used `unknown` with type guards
- [ ] **i18n**: User-facing strings use `t()` from i18n
- [ ] **Timeouts**: Async operations have configured timeout
- [ ] **Read before Write**: Read files before editing them
- [ ] **Tests**: Added tests for new features/fixes
- [ ] **Linting**: `npm run lint` passes without errors
- [ ] **Type check**: `npm run type-check` passes without errors
- [ ] **Local tests**: `npm test` passes locally
- [ ] **DCO**: Signed commits with `git commit -s`
- [ ] **Conventional Commits**: Commit messages follow `type(scope): description` format

## Impact

<!-- Mark affected areas -->

- [ ] CLI (`apps/cli-verifier`)
- [ ] MCP Server (`apps/mcp-server`)
- [ ] VSCode Extension (`apps/vscode-extension`)
- [ ] Core Library (`libs/core`)
- [ ] Security Rules (`libs/core/domain/security/rules`)
- [ ] Fuzzer (`libs/fuzzer`)
- [ ] Transport Layer (`libs/transport`)
- [ ] Shared Utils (`libs/shared`)
- [ ] Documentation
- [ ] Tests
- [ ] CI/CD

## New Dependencies

<!-- If you added dependencies, list here and justify -->

<!-- Example:
- `zod@3.22.0` - Schema validation for new feature X
- License: MIT
-->

N/A

## Breaking Changes

<!-- Does this PR break compatibility with previous versions? -->

- [ ] YES - This PR has breaking changes (describe below)
- [x] NO - This PR is backward compatible

<!-- If you marked YES, describe the breaking changes:

### What broke:
...

### How to migrate:
...
-->

## Testing

<!-- Describe how to test this PR -->

### Automated Tests

<!-- Example:
- `npm test -- path/to/test.spec.ts`
- Tests added in `libs/core/domain/security/rules/__tests__/new-rule.spec.ts`
-->

### Manual Tests

<!-- Example:
1. Run `npm run dev`
2. Execute `node dist/mcp-verify.js validate "node server.js"`
3. Verify that the new rule detects the pattern
-->

## Screenshots / Output

<!-- If applicable, add screenshots, logs, or command output -->

<details>
<summary>Example output</summary>

```bash
# Paste your manual test output here
```

</details>

## Reviewer Checklist

<!-- For the maintainer reviewing the PR -->

- [ ] Code follows `AGENTS.md` standards
- [ ] Tests cover critical cases
- [ ] Documentation updated if needed
- [ ] No hardcoded secrets
- [ ] Performance is acceptable
- [ ] Security validated (if applicable)
- [ ] CI checks passed (tests, lint, type-check, build)

## Related To

<!-- Link related issues -->

Closes #<!-- issue number -->

---

**✅ This PR will be automatically reviewed via GitHub Actions:**

- **Tests**: Unit, integration, and security test verification
- **Linting**: Code style validation with ESLint
- **Type Checking**: TypeScript types compilation
- **Build**: Project build verification
