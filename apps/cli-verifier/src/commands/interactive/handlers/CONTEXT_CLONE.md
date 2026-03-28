# Context Clone Command

> Deep copy contexts with all configuration (profile, target, language)

---

## Syntax

```bash
context clone <source> <new_name> [--target "new_url"]
```

---

## Description

Clones an existing workspace context into a new one, preserving:
- **Security profile** (deep copy with `structuredClone()`)
- **Configuration overrides** (context-specific settings)
- **Language preference**
- **Target** (URL/command) - can be overridden with `--target` flag

**Key feature**: Uses `structuredClone()` for true deep copy, ensuring no shared references between contexts. Modifying the security profile in the cloned context won't affect the original.

---

## Examples

### 1. Basic Clone
```bash
> context clone dev staging
✓ Context cloned: dev → staging
  Cloned configuration:
    Target:   node server.js
    Language: en
    Profile:  balanced

  Switch to new context: context switch staging
```

### 2. Clone with Target Override
```bash
> context clone dev prod --target "http://prod.example.com"
✓ Context cloned: dev → prod
  Cloned configuration:
    Target:   http://prod.example.com
    Language: en
    Profile:  aggressive

  ⚠️  Target overridden: http://prod.example.com

  Switch to new context: context switch prod
```

### 3. Error Cases
```bash
# Source doesn't exist
> context clone nonexistent staging
✗ Source context "nonexistent" does not exist.
  Available contexts: dev, default

# Target already exists
> context clone dev default
✗ Context "default" already exists.
  Choose a different name or delete the existing context first.
```

---

## Implementation Details

### Deep Copy Strategy

The implementation uses `structuredClone()` (Node.js 17+) instead of shallow spread operator:

**Before (createContext with baseOnActive: true)**:
```typescript
// ❌ Shallow copy - shared references!
const newContext = { ...activeContext };
```

**After (cloneContext)**:
```typescript
// ✅ Deep copy - no shared references
const clonedContext = structuredClone(sourceContext);
```

### Security Profile Structure

The `SecurityProfile` has 5 nested objects that require deep cloning:

```typescript
interface SecurityProfile {
  name: string;
  isPreset: boolean;
  enabledBlocks: SecurityRuleBlock[];
  fuzzing: { useMutations, mutationsPerPayload, maxPayloadsPerTool, enableFeedbackLoop };
  validation: { minSecurityScore, failOnCritical, failOnHigh };
  generators: { enablePromptInjection, enableClassicPayloads, ... };
  detectors: { enableTimingDetection, timingAnomalyMultiplier, ... };
}
```

Without deep copy, modifying `clonedContext.profile.fuzzing.useMutations` would also modify the original context's profile.

---

## Files Modified

### 1. `session.ts`
```typescript
cloneContext(
  source: string,
  targetName: string,
  overrides?: Partial<WorkspaceContext>
): boolean
```
- Verifies source exists and target doesn't exist
- Deep copies using `structuredClone()`
- Applies overrides (target, profile, config, etc.)
- Updates timestamps (createdAt, modifiedAt)
- Persists atomically via `persistContext()`

### 2. `handlers/context-clone.ts` (NEW)
- Parses arguments with `ShellParser.extractPositionals()` and `extractFlags()`
- Validates syntax (requires source + target name)
- Extracts `--target` flag override
- Provides clear success/error feedback with chalk
- Shows cloned configuration details

### 3. `router.ts`
- Imports `handleContextClone`
- Adds `case 'clone'` in `handleContextDispatch()` switch
- Updates `showContextHelp()` with clone documentation and examples

### 4. `completer.ts`
- Adds `'clone'` to `COMMAND_FLAGS['context']` array
- Enables TAB completion: `context c[TAB]` → `context clone`

### 5. `handlers/info.ts`
- Updates `showHelp()` to include `clone` in context subcommands

---

## Workflow Example

```bash
# 1. Create dev context with aggressive profile
> profile set aggressive
> target node server.js
> config
  Profile: aggressive
  Target:  node server.js

# 2. Clone to staging with different target
> context clone dev staging --target "http://staging:3000"
✓ Context cloned: dev → staging

# 3. Verify staging has independent configuration
> context switch staging
> config
  Profile: aggressive (deep copy - independent)
  Target:  http://staging:3000

# 4. Modify staging profile without affecting dev
> profile set light
> context switch dev
> config
  Profile: aggressive (unchanged!)
```

---

## Testing

To verify deep copy works correctly:

1. Clone a context with aggressive profile
2. Switch to cloned context
3. Modify the profile (e.g., disable prompt injection)
4. Switch back to original context
5. Verify original profile is unchanged

```bash
> context create test1
> context switch test1
> profile set aggressive
> context clone test1 test2
> context switch test2
> # Modify test2 profile settings via config overrides
> set fuzzing.useMutations false
> context switch test1
> config  # Should show useMutations: true (unchanged)
```

---

## Architecture Notes

- **ATOMIC**: All persistence uses `persistContext()` which calls `PersistenceManager.saveWorkspaceContexts()` with atomic write-then-rename pattern
- **VALIDATION**: Method returns `boolean` success status for error handling
- **TIMESTAMPS**: Always updates `createdAt` and `modifiedAt` for audit trail
- **OVERRIDES**: Supports `Partial<WorkspaceContext>` for flexible extensibility (currently used for `target`, but can be extended for profile, lang, etc.)

---

## Future Enhancements

Potential extensions for `cloneContext()`:

1. **Multiple overrides**: `--target`, `--profile`, `--lang` flags
2. **Selective cloning**: `--no-profile` to use default profile instead of cloning
3. **Bulk clone**: `context clone-all <suffix>` to clone all contexts (dev → dev-backup)
4. **Template cloning**: `context clone --template <preset>` to clone with preset modifications

---

**Last Updated**: 2026-03-06
**Added in**: v1.0.1 (post-refactoring)
