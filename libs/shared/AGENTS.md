# @mcp-verify/shared — Agent Context

**Mission**: Pure utilities kernel and security perimeter of the monorepo. All untrusted input passes through here before reaching `core` or the apps.

---

## Logical Architecture

```
libs/shared/src/
├── logger/               # Singleton Logger (structured, redacts secrets)
├── services/             # Shared services (api-key-manager, user-agent, git-info)
└── utils/
    ├── path-validator.ts     # ★ Path traversal guard — MANDATORY
    ├── url-validator.ts      # ★ URL sanitization — MANDATORY
    ├── regex-safe.ts         # ★ ReDoS prevention — MANDATORY
    ├── deep-merge.ts         # Type-safe object merge
    ├── command-normalizer.ts # Normalize CLI command strings
    ├── smart-launcher.ts     # Cross-platform process launcher
    ├── json.ts               # Safe JSON parse (never throws)
    └── cli/
        ├── i18n-helper.ts    # ★ t() wrapper — MANDATORY for UI strings
        ├── error-formatter.ts
        ├── output-helper.ts
        └── external-editor.ts
```

### Golden Rule: Zero Internal Imports

```typescript
// ❌ NEVER inside libs/shared/
import { anything } from "@mcp-verify/core";
import { anything } from "@mcp-verify/fuzzer";

// ✅ ONLY external deps or internal relative imports
import { z } from "zod";
import { pathValidator } from "../utils/path-validator";
```

`shared` is the base of the pyramid. It cannot import from anything that imports it.

---

## Tier-S: Components You Never Skip

| Component                  | File                       | Sin if skipped                                |
| -------------------------- | -------------------------- | --------------------------------------------- |
| `pathValidator.validate()` | `utils/path-validator.ts`  | Path traversal → RCE/LFI in MCP tools         |
| `urlValidator.validate()`  | `utils/url-validator.ts`   | SSRF, open redirect, protocol injection       |
| `t('key')`                 | `utils/cli/i18n-helper.ts` | Hardcoded string breaks i18n (global rule #2) |
| `regexSafe.compile()`      | `utils/regex-safe.ts`      | ReDoS: untrusted input can hang the process   |

**Correct usage:**

```typescript
import { pathValidator, urlValidator, regexSafe, t } from "@mcp-verify/shared";

// Path
const safe = pathValidator.validate(userInput, { allowedRoot: "/tmp/mcp" });
if (!safe.ok) throw new ValidationError(t("invalid_path"));

// URL
const url = urlValidator.validate(rawUrl, { protocols: ["https"] });

// Regex
const re = regexSafe.compile(userPattern, { timeout: 100 });
```

---

## Extension Guide: Adding a Utility

**1. Create the file** in the right folder:

```bash
# Pure utility → utils/
touch libs/shared/src/utils/my-util.ts

# CLI helper (chalk, ora, inquirer) → utils/cli/
touch libs/shared/src/utils/cli/my-cli-util.ts
```

**2. Export from the barrel:**

```typescript
// libs/shared/src/index.ts
export * from "./utils/my-util";
```

**3. Checklist before committing:**

- [ ] Zero imports from `@mcp-verify/core` or `@mcp-verify/fuzzer`
- [ ] External input validated with Zod + Tier-S guard if touching paths/URLs
- [ ] UI strings use `t()`, no literals
- [ ] Test in `libs/shared/src/__tests__/` with ≥ 95% coverage if security-related

---

## Testing

```bash
npm test -- libs/shared
npm test -- libs/shared --coverage
```

| Area                   | Min coverage                |
| ---------------------- | --------------------------- |
| `utils/path-validator` | **95%** — security critical |
| `utils/url-validator`  | **95%** — security critical |
| `utils/regex-safe`     | **95%** — security critical |
| `utils/cli/*`          | 70%                         |
| Rest of `utils/`       | 80%                         |
| `logger/`              | 60% (real I/O)              |

Tests at: `libs/shared/src/__tests__/` (mirrors `src/` structure).

---

**Last Updated**: 2026-03-31 | Maintainer: @FinkTech via Claude Code
