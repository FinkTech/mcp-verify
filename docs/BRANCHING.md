# Branching Strategy

> **Quick Start**: We use Git Flow. Fork the repo, create a feature branch from `develop`, make your changes, and open a PR. We'll guide you through the rest!

Welcome to MCP Verify! This guide explains how we organize our git branches and how you can contribute to the project. Whether you're a first-time contributor or an experienced developer, we've designed our workflow to be clear and collaborative.

---

## 📚 Table of Contents

- [Why Git Flow?](#why-git-flow)
- [Branch Structure](#branch-structure)
- [Contributing Your First Feature](#contributing-your-first-feature)
- [Workflow Examples](#workflow-examples)
- [Branch Protection & CI](#branch-protection--ci)
- [Commit Standards](#commit-standards)
- [FAQ](#faq)

---

## Why Git Flow?

We chose Git Flow because it provides:

✅ **Clear Separation**: Production code (`main`) is always stable and deployable
✅ **Parallel Development**: Multiple features can be developed simultaneously on `develop`
✅ **Release Control**: We can prepare releases carefully before shipping to npm
✅ **Emergency Fixes**: Hotfixes can go straight to production when needed
✅ **Community Friendly**: Well-documented pattern that most developers recognize

**TL;DR**: `main` = what users download from npm. `develop` = where new features come together.

---

## Branch Structure

### 🌳 Permanent Branches (Never Deleted)

<table>
<thead>
<tr>
<th>Branch</th>
<th>Purpose</th>
<th>Who Can Push</th>
<th>Deployment</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>main</code></td>
<td>
<strong>Production-ready code</strong><br>
Every commit here is a stable release that gets published to npm. Users download this version.
</td>
<td>
Maintainers only<br>
(via PR from <code>release/*</code> or <code>hotfix/*</code>)
</td>
<td>
📦 npm registry<br>
🏷️ Tagged versions (v1.0.0)
</td>
</tr>
<tr>
<td><code>develop</code></td>
<td>
<strong>Integration branch</strong><br>
Where all feature branches merge. Contains the latest development changes for the next release.
</td>
<td>
Contributors via PR<br>
Maintainers for merges
</td>
<td>
🔍 Preview builds<br>
🧪 Internal testing
</td>
</tr>
</tbody>
</table>

### 🌿 Temporary Branches (Created & Deleted)

<table>
<thead>
<tr>
<th>Pattern</th>
<th>Purpose</th>
<th>Created From</th>
<th>Merged Into</th>
<th>Examples</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>feature/*</code></td>
<td>
<strong>New features</strong><br>
Adding new functionality, capabilities, or improvements
</td>
<td><code>develop</code></td>
<td><code>develop</code><br>(squash merge)</td>
<td>
<code>feature/websocket-transport</code><br>
<code>feature/prometheus-metrics</code>
</td>
</tr>
<tr>
<td><code>bugfix/*</code></td>
<td>
<strong>Non-urgent bug fixes</strong><br>
Fixing bugs that can wait for the next regular release
</td>
<td><code>develop</code></td>
<td><code>develop</code><br>(squash merge)</td>
<td>
<code>bugfix/fix-timeout-issue</code><br>
<code>bugfix/memory-leak-fuzzer</code>
</td>
</tr>
<tr>
<td><code>docs/*</code></td>
<td>
<strong>Documentation only</strong><br>
README updates, guides, examples, typo fixes
</td>
<td><code>develop</code></td>
<td><code>develop</code><br>(squash merge)</td>
<td>
<code>docs/update-readme</code><br>
<code>docs/add-security-guide</code>
</td>
</tr>
<tr>
<td><code>hotfix/*</code></td>
<td>
<strong>⚠️ Urgent production fixes</strong><br>
Critical bugs in production that can't wait (maintainers only)
</td>
<td><code>main</code></td>
<td><code>main</code> + <code>develop</code><br>(merge commit)</td>
<td>
<code>hotfix/critical-security-cve</code><br>
<code>hotfix/npm-publish-failure</code>
</td>
</tr>
<tr>
<td><code>release/*</code></td>
<td>
<strong>📦 Release preparation</strong><br>
Preparing a new version for npm (maintainers only)
</td>
<td><code>develop</code></td>
<td><code>main</code> + <code>develop</code><br>(merge commit)</td>
<td>
<code>release/1.1.0</code><br>
<code>release/2.0.0-beta.1</code>
</td>
</tr>
</tbody>
</table>

---

## Contributing Your First Feature

**Never contributed to open source before? No problem!** Here's a step-by-step guide:

### Step 1: Fork & Clone

1. **Fork the repository** on GitHub (click the "Fork" button)
2. **Clone your fork** to your computer:

```bash
git clone https://github.com/YOUR-USERNAME/mcp-verify.git
cd mcp-verify
```

3. **Add the original repo as "upstream"** (so you can sync later):

```bash
git remote add upstream https://github.com/FinkTech/mcp-verify.git
```

### Step 2: Create Your Feature Branch

Always create a new branch from `develop`:

```bash
# Make sure you're starting from develop
git checkout develop

# Pull latest changes from upstream
git fetch upstream
git merge upstream/develop

# Create your feature branch
git checkout -b feature/my-awesome-feature
```

### Step 3: Make Your Changes

- **Write code**: Follow the patterns in [AGENTS.md](../AGENTS.md)
- **Test locally**: Run `npm test` to make sure tests pass
- **Lint your code**: Run `npm run lint` to check code style

### Step 4: Commit with DCO

We require **Developer Certificate of Origin (DCO)** sign-off on all commits. This certifies that you wrote the code or have the right to submit it.

```bash
# The -s flag adds the DCO sign-off automatically
git commit -s -m "feat(scanner): add SQL injection detection for PostgreSQL"
```

**Commit message format**: `<type>(<scope>): <description>`

- Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`
- Scope: Which part of the code (e.g., `cli`, `scanner`, `fuzzer`)
- Description: What you did in present tense

### Step 5: Push & Create PR

```bash
# Push to your fork
git push origin feature/my-awesome-feature
```

Then go to GitHub and click **"Create Pull Request"**. Make sure to:

- ✅ Target the `develop` branch (not `main`)
- ✅ Describe what your PR does
- ✅ Reference any related issues

### Step 6: Review Process

1. **Automated checks run**: CI tests, linting, and optional code quality checks
2. **Maintainer reviews** your code
3. **Address feedback** if requested (push new commits)
4. **PR gets merged** (squashed into a single commit on `develop`)

🎉 **Congratulations!** You're now a contributor to MCP Verify!

---

## Workflow Examples

### 🛠️ Example 1: Adding a New Security Rule

You want to add detection for NoSQL injection attacks.

```bash
# 1. Sync with upstream
git checkout develop
git pull upstream develop

# 2. Create feature branch
git checkout -b feature/nosql-injection-rule

# 3. Create your rule file
# Create: libs/core/domain/security/rules/nosql-injection.rule.ts
# Write tests in: libs/core/domain/security/rules/nosql-injection.rule.spec.ts

# 4. Run tests locally
npm test

# 5. Commit with DCO sign-off
git add .
git commit -s -m "feat(security): add NoSQL injection detection rule

- Detects MongoDB, Cassandra, and DynamoDB injection patterns
- Includes 15+ test cases covering various attack vectors
- Adds to default security profile"

# 6. Push to your fork
git push origin feature/nosql-injection-rule

# 7. Open PR on GitHub targeting 'develop'
```

### 📝 Example 2: Fixing a Typo in Documentation

```bash
# 1. Create docs branch
git checkout -b docs/fix-readme-typo develop

# 2. Fix the typo in README.md
# ... edit file ...

# 3. Commit
git commit -s -m "docs(readme): fix typo in installation section"

# 4. Push and create PR
git push origin docs/fix-readme-typo
```

### 🐛 Example 3: Fixing a Bug

You found that the CLI times out when scanning large servers.

```bash
# 1. Create bugfix branch
git checkout -b bugfix/cli-timeout-large-servers develop

# 2. Fix the issue
# Edit: apps/cli-verifier/src/commands/validate.ts

# 3. Add test to prevent regression
# Edit: apps/cli-verifier/src/commands/__tests__/validate.spec.ts

# 4. Run tests
npm test

# 5. Commit with clear description
git commit -s -m "fix(cli): increase timeout for large server scans

- Timeout was hardcoded to 30s, now scales with server size
- Adds progress indicator for long-running scans
- Includes test with mock server containing 100+ tools"

# 6. Push and create PR
git push origin bugfix/cli-timeout-large-servers
```

### 🔥 Example 4: Hotfix (Maintainers Only)

A critical security vulnerability was discovered in production.

```bash
# 1. Create hotfix from main
git checkout main
git checkout -b hotfix/critical-path-traversal

# 2. Fix the vulnerability
# ... make changes ...

# 3. Test thoroughly
npm test
npm run test:security

# 4. Commit
git commit -s -m "fix(security): patch critical path traversal vulnerability

CVE-2024-XXXXX: Prevents directory traversal in file upload validation"

# 5. Merge to main (triggers npm publish)
git checkout main
git merge --no-ff hotfix/critical-path-traversal
git tag -a v1.0.1 -m "Hotfix: Critical security patch (CVE-2024-XXXXX)"
git push origin main --tags

# 6. Merge back to develop
git checkout develop
git merge --no-ff hotfix/critical-path-traversal
git push origin develop

# 7. Delete hotfix branch
git branch -d hotfix/critical-path-traversal
```

### 📦 Example 5: Preparing a Release (Maintainers Only)

Time to ship v1.1.0 to npm!

```bash
# 1. Create release branch from develop
git checkout -b release/1.1.0 develop

# 2. Update version in all package.json files
npm version 1.1.0 --no-git-tag-version

# 3. Update CHANGELOG.md with release notes
# ... edit CHANGELOG.md ...

# 4. Commit release preparation
git commit -s -m "chore(release): prepare v1.1.0

- Update package versions
- Add CHANGELOG entries
- Update README badges"

# 5. Merge to main (triggers CI/CD pipeline)
git checkout main
git merge --no-ff release/1.1.0
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin main --tags

# 6. Merge back to develop
git checkout develop
git merge --no-ff release/1.1.0
git push origin develop

# 7. Delete release branch
git branch -d release/1.1.0

# CI/CD will automatically publish to npm registry
```

---

## Branch Protection & CI

### 🔒 Protection Rules

#### `main` Branch

```yaml
✅ Require pull request before merging
✅ Require 1 approval from maintainer
✅ Dismiss stale approvals when new commits pushed
✅ Require status checks to pass
- ci (GitHub Actions - tests, linting, type checking)
✅ Require signed commits (recommended)
✅ Require linear history
✅ Do not allow bypassing settings
```

#### `develop` Branch

```yaml
✅ Require pull request before merging
✅ Require status checks to pass
- ci (GitHub Actions)
✅ Allow administrators to bypass (for emergency hotfix merges)
```

### 🤖 Automated Checks

When you open a PR, these checks run automatically via GitHub Actions:

<table>
<thead>
<tr>
<th>Check</th>
<th>What It Does</th>
<th>How to Fix Failures</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>CI Tests</strong></td>
<td>
Runs <code>npm test</code> for unit, integration, and security tests
</td>
<td>
Run <code>npm test</code> locally and fix failing tests
</td>
</tr>
<tr>
<td><strong>Linting</strong></td>
<td>
Checks code style with ESLint
</td>
<td>
Run <code>npm run lint</code> and fix reported issues
</td>
</tr>
<tr>
<td><strong>Type Checking</strong></td>
<td>
Verifies TypeScript types compile without errors
</td>
<td>
Run <code>npm run type-check</code> and fix type errors
</td>
</tr>
<tr>
<td><strong>Build Verification</strong></td>
<td>
Ensures the project builds successfully on all platforms
</td>
<td>
Run <code>npm run build</code> and fix build errors
</td>
</tr>
</tbody>
</table>

### 🔍 Periodic Code Quality Reviews

In addition to automated checks, we run periodic code quality audits using internal tooling:

- **Architecture Review**: Validates code structure, checks for `any` types, ensures i18n compliance
- **License Compliance**: Scans dependencies for incompatible licenses
- **Security Audits**: Reviews security rule implementations for correctness

These reviews run **locally on scheduled intervals** (typically weekly) and help maintain code quality standards. Results are shared with maintainers for follow-up action when needed.

---

## Commit Standards

We use **Conventional Commits** + **DCO Sign-off**.

### ✅ Good Commit Messages

```bash
feat(fuzzer): add SQL injection payloads for PostgreSQL
fix(cli): resolve timeout in interactive mode
docs(readme): update installation instructions
test(security): add path traversal rule tests
refactor(scanner): extract validation logic into separate class
chore(deps): upgrade TypeScript to 5.3.0
```

### ❌ Bad Commit Messages

```bash
fixed bug                    # No type, no scope, too vague
update code                  # What code? What update?
WIP                          # Not descriptive enough
asdf                         # Really?
```

### 📝 Commit Message Format

```
<type>(<scope>): <description>

[optional body explaining WHY this change was needed]

[optional footer with issue references]

Signed-off-by: Your Name <your.email@example.com>
```

**Types**:

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Code formatting (no logic change)
- `refactor` - Code restructuring (no behavior change)
- `perf` - Performance improvement
- `test` - Adding or fixing tests
- `chore` - Maintenance (dependencies, build, etc.)
- `ci` - CI/CD changes
- `revert` - Revert a previous commit

**Scopes**: `cli`, `scanner`, `fuzzer`, `vscode-ext`, `mcp-server`, `security`, `core`, `protocol`, `docs`

### 🔐 DCO Sign-off

All commits **must** be signed off with the Developer Certificate of Origin:

```bash
# Use -s flag to automatically add DCO
git commit -s -m "feat(cli): add new validation mode"

# This adds to your commit:
# Signed-off-by: Your Name <your.email@example.com>
```

**What is DCO?** It's a lightweight way (used by Linux, Docker, Kubernetes) to certify you have the right to submit your code. By signing off, you're confirming:

> I certify that I wrote this code or have the right to submit it, and I understand it will be distributed under the AGPL-3.0 license.

**Without DCO sign-off, your PR will be rejected.**

---

## Visual Flow Diagram

```
                                    🔥 hotfix/* ─────────────────────┐
                                         │                           │
                                         │                           ▼
    🌿 feature/* ──┐                     │                         main ────► 📦 npm publish
    🐛 bugfix/*  ──┼────► develop ──► 📦 release/*                   │        (production)
    📝 docs/*    ──┘         ▲                                       │
                             │                                       │
                             └───────────────────────────────────────┘
                                        (merge back)

Timeline Example:
  Week 1-2:  Contributors submit PRs to develop
  Week 3:    Stabilization & testing on develop
  Week 4:    Create release/1.x.0 → merge to main → publish to npm
```

---

## FAQ

<details>
<summary><strong>Can I create a PR from my fork's <code>main</code> branch?</strong></summary>

**No.** Always create a feature branch. PRs from `main` won't be accepted.

```bash
# ❌ Don't do this
git checkout main
# ... make changes ...
git push origin main  # ← This creates a PR from main

# ✅ Do this instead
git checkout -b feature/my-feature develop
# ... make changes ...
git push origin feature/my-feature  # ← This creates a PR from a feature branch
```

</details>

<details>
<summary><strong>Can I force push to my feature branch?</strong></summary>

**Yes, but only before the PR is approved.** After approval, avoid force pushing as it can confuse reviewers.

```bash
# Before approval: OK to rewrite history
git commit --amend
git push --force origin feature/my-feature

# After approval: Just add new commits
git commit -m "fix: address review feedback"
git push origin feature/my-feature
```

</details>

<details>
<summary><strong>How do I sync my fork with upstream?</strong></summary>

```bash
# Fetch latest changes from upstream
git fetch upstream

# Switch to your develop branch
git checkout develop

# Merge upstream changes
git merge upstream/develop

# Push to your fork
git push origin develop
```

Do this regularly to avoid merge conflicts!

</details>

<details>
<summary><strong>What if CI checks fail on my PR?</strong></summary>

1. **Check the CI logs** on GitHub Actions tab
2. **Read the error messages** - they usually tell you what's wrong
3. **Fix the issues** locally by running the same checks:
   ```bash
   npm test           # Run tests
   npm run lint       # Check linting
   npm run type-check # Check types
   npm run build      # Verify build
   ```
4. **Push new commits** - CI will re-run automatically
5. **Ask for help** if you're stuck (comment on the PR)

Example: CI shows 3 failing tests. Run `npm test` locally, fix the tests, commit, and push.

</details>

<details>
<summary><strong>Can I skip DCO sign-off?</strong></summary>

**No.** All commits must have DCO sign-off. PRs without DCO will be auto-rejected.

```bash
# Configure git to always sign-off
git config --global format.signoff true

# Now all commits will be signed automatically
git commit -m "feat: add feature"  # ← Automatically signed
```

</details>

<details>
<summary><strong>Which branch should I target for my PR?</strong></summary>

- **Features, bugfixes, docs** → `develop`
- **Hotfixes** → `main` (maintainers only)
- **When in doubt** → `develop`

The PR template will guide you.

</details>

<details>
<summary><strong>Can I merge my own PR?</strong></summary>

**No.** All PRs require review from a maintainer. We value collaborative review!

</details>

<details>
<summary><strong>How long until my PR is reviewed?</strong></summary>

We aim to review PRs within **48-72 hours**. If you haven't heard back after 5 days, feel free to ping us with a comment.

</details>

<details>
<summary><strong>Can I work on multiple features at the same time?</strong></summary>

**Yes!** Just create separate branches for each feature:

```bash
git checkout -b feature/add-redis-cache develop
# ... work on caching ...
git push origin feature/add-redis-cache

git checkout develop  # Go back to develop
git checkout -b feature/add-graphql-api develop
# ... work on GraphQL ...
git push origin feature/add-graphql-api
```

</details>

<details>
<summary><strong>I made a mistake in my commit message. How do I fix it?</strong></summary>

If you haven't pushed yet:

```bash
# Fix the last commit message
git commit --amend -m "fix(cli): correct commit message"
```

If you already pushed:

```bash
# Fix and force push (only if PR not approved yet)
git commit --amend -m "fix(cli): correct commit message"
git push --force origin feature/my-branch
```

</details>

---

## Additional Resources

- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Full contribution guide
- **[AGENTS.md](../AGENTS.md)** - Code standards and architecture
- **[DEVELOPMENT.md](../DEVELOPMENT.md)** - Local development setup
- **[Git Flow Explained](https://nvie.com/posts/a-successful-git-branching-model/)** - Original Git Flow article

---

**Questions?** Open a [GitHub Discussion](https://github.com/FinkTech/mcp-verify/discussions) or ask in the PR comments. We're here to help! 🚀
