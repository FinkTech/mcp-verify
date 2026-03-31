# 📉 Regression Detection Guide

Track security score changes across scans, prevent regressions in CI/CD pipelines, and catch newly introduced vulnerabilities before they reach production.

---

## 🧭 Overview

**Regression Detection** is a core feature of `mcp-verify` that allows you to snapshot the security and quality state of an MCP server at a given point in time — called a **baseline** — and then compare future scans against it.

Instead of only asking *"What issues exist today?"*, you can now ask:

- *"Did we introduce new vulnerabilities since the last release?"*
- *"Did the security score drop after merging this PR?"*
- *"What problems did we fix? What new ones came in?"*

This is especially valuable in **CI/CD pipelines**, where you want to automatically block deployments that introduce critical security regressions, even if the overall validation still passes.

### Why it matters

| Without Regression Detection          | With Regression Detection                      |
|---------------------------------------|------------------------------------------------|
| ✅ Score: 72 — build passes           | ✅ Score: 72 — but wait...                     |
| Silent regression goes unnoticed      | ⚠️ Score dropped 8 points from baseline        |
| New CRITICAL finding is just a number | 🚨 Build fails: new CRITICAL finding detected  |
| No record of what changed             | 📋 Diff: 2 new issues, 1 resolved              |

---

## ⚡ Quick Start

A two-step workflow: **save a baseline**, then **compare against it**.

### Step 1 — Save the current state as baseline

Run this once against your stable, known-good server state (e.g., on your `main` branch):

```bash
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
```

This creates a JSON snapshot file at the path you specify. The file contains scores, finding counts, and a hash of every detected vulnerability.

### Step 2 — Compare a future scan against the baseline

Run this on every PR, commit, or deployment:

```bash
mcp-verify validate "node server.js" --compare-baseline reports/baseline/main.json
```

The output will show:

- **Security Score delta** — how much it changed vs. baseline
- **Quality Score delta** — same for quality
- **New Issues** — vulnerabilities that weren't in the baseline
- **Resolved Issues** — vulnerabilities that were fixed since the baseline
- **Status** — one of `improved`, `unchanged`, `degraded`, or `critical_degradation`

### Step 3 — Fail CI/CD on regression (optional but recommended)

```bash
mcp-verify validate "node server.js" \
  --compare-baseline reports/baseline/main.json \
  --fail-on-degradation \
  --allowed-score-drop 5
```

If the security score drops more than 5 points, or a new `CRITICAL` vulnerability appears, the command exits with code `2` and fails the build.

---

## 🔧 CLI Reference

All regression-related flags are used with the `validate` command.

### Flags

| Flag                      | Argument   | Default | Description                                                                  |
|---------------------------|------------|---------|------------------------------------------------------------------------------|
| `--save-baseline`         | `<path>`   | `—`     | Save current scan results as a baseline snapshot to the given file path        |
| `--compare-baseline`      | `<path>`   | `—`     | Load and compare the current scan against the baseline at the given path       |
| `--fail-on-degradation`   | —          | `false` | Exit with code `2` if the score drops beyond the allowed threshold             |
| `--allowed-score-drop`    | `<number>` | `5`     | Maximum allowed score drop (in points) before `--fail-on-degradation` triggers |

> **Note:** `--save-baseline` and `--compare-baseline` can be used **together** in a single command. This is useful for pipelines where you want to update the baseline and still check for regressions in the same step.

### Flag Details

#### `--save-baseline <path>`

Saves a snapshot of the current scan to a `.json` file at the specified path. Directories in the path are created automatically if they don't exist.

```bash
# Recommended: organize baselines by branch or environment
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
mcp-verify validate "node server.js" --save-baseline reports/baseline/production.json
```

The snapshot includes: security/quality/protocol scores, tool/resource/prompt counts, finding severity counts, and a content hash of each finding for diff detection.

#### `--compare-baseline <path>`

Loads the baseline from the given path and produces a comparison report showing what changed since the snapshot was taken.

```bash
mcp-verify validate "node server.js" --compare-baseline reports/baseline/main.json
```

If the file does not exist, the command will warn and continue without comparison.

#### `--fail-on-degradation`

Enables strict regression enforcement. When present, the command exits with code `2` (build failure) if:

- A new `CRITICAL` severity vulnerability is detected (always enforced when this flag is set), **or**
- The security or quality score drops more than `--allowed-score-drop` points

Without this flag, regressions are reported informally but do **not** fail the build.

#### `--allowed-score-drop <number>`

Sets a tolerance margin for score drops. Defaults to `5`. Only relevant when `--fail-on-degradation` is active.

```bash
# Strict mode: no score drops allowed
mcp-verify validate "node server.js" \
  --compare-baseline baseline.json \
  --fail-on-degradation \
  --allowed-score-drop 0

# Lenient mode: allow up to 10 point drop
mcp-verify validate "node server.js" \
  --compare-baseline baseline.json \
  --fail-on-degradation \
  --allowed-score-drop 10
```

---

## 🚦 Exit Codes

| Code | Meaning            | When it occurs                                                              |
|------|--------------------|-----------------------------------------------------------------------------|
| `0`  | ✅ Success         | Scan completed, no critical issues or regression detected                   |
| `1`  | ❌ Command error   | Invalid arguments, connection failure, or unhandled runtime error           |
| `2`  | 🚨 Critical Issue  | New CRITICAL findings detected **OR** regression found via `--fail-on-degradation` |

> **CI/CD tip:** Always check exit codes explicitly. A `2` should fail the pipeline step. A `1` may indicate an infrastructure problem (e.g., server unreachable) and may warrant a separate alert.

### Failure logic (from source)

The command returns exit code `2` when **any** of the following is true:

1. **New CRITICAL findings** — **(Always enforced)** If any new `CRITICAL` vulnerability is detected compared to the baseline, the build fails. This is a hard security gate that works even without the `--fail-on-degradation` flag.

2. **Score drop exceeds threshold** — (Requires `--fail-on-degradation`) If the security or quality score drops by more than the value of `--allowed-score-drop` (default: `5`).

```
if (newCriticalFindings > 0)          → exit 2  (hard security gate)
if (securityDrop > allowedScoreDrop)  → exit 2  (if --fail-on-degradation)
if (qualityDrop > allowedScoreDrop)   → exit 2  (if --fail-on-degradation)
```

---

## 📈 Summary of Regression Logic

**Regression Detection** creates a **content hash** for each finding based on its rule code, affected component, and severity level:

```
hash = ruleCode + ":" + component + ":" + severity
```

These hashes are stored in the baseline and compared to the current scan. This means:

- **New Issues** = hashes present in the current scan but not in the baseline
- **Resolved Issues** = hashes present in the baseline but not in the current scan

This approach correctly identifies regressions even when the total finding count stays the same (e.g., one issue fixed, a different one introduced).

---

## 🗄️ Storage Structure

You are responsible for managing your baseline files. We recommend storing them in `reports/baseline/` and committing them to your repository.

Separately, `mcp-verify` can maintain an automatic history of every scan in:
```
.mcp-verify/history/
```
These historical files are used for the `history` command and trend analysis, but are distinct from the explicit baseline files you create with `--save-baseline`.

---

## 🏭 CI/CD Use Cases

### GitHub Actions — PR Security Gate

This workflow enforces that no PR introduces a CRITICAL vulnerability or drops the security score significantly.

```yaml
name: MCP Security Gate

on:
  pull_request:
    branches: [main]

jobs:
  security-regression:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install mcp-verify
        run: npm install -g mcp-verify

      - name: Download baseline from main branch
        uses: actions/download-artifact@v4
        with:
          name: mcp-verify-baseline
          path: reports/baseline/

      - name: Run security regression check
        run: |
          mcp-verify validate "node server.js" \
            --compare-baseline reports/baseline/main.json \
            --fail-on-degradation \
            --allowed-score-drop 5 \
            --format json \
            --output reports/
        # Exit code 2 = regression detected → step fails → PR blocked

      - name: Upload scan report as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mcp-verify-report-pr-${{ github.event.number }}
          path: reports/
```

### GitHub Actions — Update Baseline on Merge to Main

After a PR is approved and merged, update the baseline so future PRs are compared against the new, accepted state.

```yaml
name: Update MCP Baseline

on:
  push:
    branches: [main]

jobs:
  update-baseline:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install mcp-verify
        run: npm install -g mcp-verify

      - name: Save new baseline from main
        run: |
          mcp-verify validate "node server.js" \
            --save-baseline reports/baseline/main.json

      - name: Upload baseline as artifact
        uses: actions/upload-artifact@v4
        with:
          name: mcp-verify-baseline
          path: reports/baseline/main.json
          retention-days: 90
```

### Full Combined Workflow (Monorepo / Single Pipeline)

For teams that prefer a single pipeline file covering both scan and baseline management:

```yaml
name: MCP Full Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  mcp-security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm install -g mcp-verify

      - name: Download existing baseline (if available)
        continue-on-error: true  # First run won't have a baseline yet
        uses: actions/download-artifact@v4
        with:
          name: mcp-verify-baseline
          path: reports/baseline/

      - name: Validate and compare
        run: |
          mcp-verify validate "node server.js" \
            --compare-baseline reports/baseline/main.json \
            --save-baseline reports/baseline/main.json \
            --fail-on-degradation \
            --allowed-score-drop 5 \
            --format json \
            --output reports/

      - name: Persist updated baseline
        if: github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: mcp-verify-baseline
          path: reports/baseline/main.json
          retention-days: 90
```

> **Pattern:** On `main` pushes, the baseline is updated. On PRs, only the comparison runs (baseline artifact is downloaded but not re-uploaded, since the `if` condition restricts it to `main`).

---

## 🛠️ Troubleshooting

### ❌ `Baseline file not found` warning on first run

**Cause:** The baseline `.json` file doesn't exist yet because `--save-baseline` hasn't been run.

**Solution:** Run `--save-baseline` once against your current stable state, then commit or artifact the file. On the first CI run, use `continue-on-error: true` on the download step to gracefully handle the missing file.

```bash
# One-time setup
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
```

---

### ❌ `baseline_parse_error` on `--compare-baseline`

**Cause:** The baseline file is malformed, empty, or was saved by an incompatible version of `mcp-verify`.

**Solution:** Delete the existing baseline and regenerate it:

```bash
rm reports/baseline/main.json
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
```

---

### ❌ Exit code `2` even though no new issues are visible

**Cause:** The severity count for `CRITICAL` findings increased, even if the finding looks familiar. This can happen if a previously `HIGH` finding was re-classified as `CRITICAL` by an updated rule set.

**Solution:** Review the `New Issues` section of the comparison output. Check if a known finding changed severity. If the new classification is intentional, update the baseline:

```bash
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
```

---

### ❌ Build always passes even with obvious score drops

**Cause:** `--fail-on-degradation` was not included in the command.

**Solution:** Make sure the flag is explicitly present. It does **not** default to `true`.

```bash
# ❌ This will NOT fail on regression
mcp-verify validate "node server.js" --compare-baseline baseline.json

# ✅ This WILL fail on regression
mcp-verify validate "node server.js" --compare-baseline baseline.json --fail-on-degradation
```

---

### ❌ Baseline grows stale and every run shows regressions

**Cause:** The baseline was saved months ago and many things changed legitimately since then.

**Solution:** Periodically refresh the baseline to represent the current accepted state. Treat this as a deliberate act — like accepting technical debt — and document it in a commit message or PR description.

```bash
# Accept current state as new baseline
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
git add reports/baseline/main.json
git commit -m "chore: refresh mcp-verify security baseline"
```

---

## 🔗 Related Documentation

- **[EXAMPLES.md](./guides/EXAMPLES.md)** — Copy-paste commands for common workflows
- **[CLI README](./apps/cli-verifier/README.md)** — Full CLI command reference
- **[CODE_MAP.md](./CODE_MAP.md)** — "I want to..." quick reference for contributors
- **[libs/core/README.md](./libs/core/README.md)** — Core business logic and architecture

---

*Part of the **mcp-verify** project — the open-source security scanner for Model Context Protocol servers.*
*Licensed under [AGPL-3.0](./LICENSE). © 2026 FinkTech.*
