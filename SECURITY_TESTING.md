# Security Testing Guide

This guide explains how to run and contribute to the MCP Verify security test suite.

---

## Overview

MCP Verify includes 60 security rules organized into 6 blocks:

| Block     | Range              | Description                         | Status                 |
| --------- | ------------------ | ----------------------------------- | ---------------------- |
| **OWASP** | SEC-001 to SEC-013 | OWASP Top 10 Aligned Rules          | ✅ Enabled             |
| **MCP**   | SEC-014 to SEC-021 | MCP-Specific Security               | ✅ Enabled             |
| **A**     | SEC-022 to SEC-030 | OWASP LLM Top 10 in MCP Context     | ✅ Enabled             |
| **B**     | SEC-031 to SEC-041 | Multi-Agent & Agentic Attacks       | ✅ Enabled             |
| **C**     | SEC-042 to SEC-050 | Operational & Enterprise Compliance | ✅ Enabled             |
| **D**     | SEC-051 to SEC-060 | AI Weaponization & Supply Chain     | ⚠️ Disabled by default |

---

## Block D: AI Weaponization & Supply Chain

### Why is Block D disabled by default?

Block D contains **advanced security rules** designed to detect sophisticated attacks including:

- SEC-051: Weaponized MCP Fuzzer
- SEC-052: Autonomous MCP Backdoor
- SEC-053: Malicious Config File
- SEC-054: API Endpoint Hijacking
- SEC-055: Jailbreak as Service
- SEC-056: Phishing via MCP
- SEC-057: Data Exfiltration via Steganography
- SEC-058: Self-Replicating MCP
- SEC-059: Unvalidated Tool Authorization
- SEC-060: Missing Transaction Semantics

These rules are **intentionally disabled by default** because:

1. **False Positive Risk**: These rules detect patterns that may be legitimate in controlled environments (research labs, security testing tools, authorized fuzzing)
2. **Performance Impact**: Some rules require deep static analysis that increases scan time
3. **Opt-in Security Posture**: Organizations should explicitly enable weaponization detection based on their threat model
4. **Compliance Requirements**: Not all regulatory frameworks require this level of detection

### When should you enable Block D?

Enable Block D when:

- ✅ Running comprehensive security audits
- ✅ Scanning third-party/untrusted MCP servers
- ✅ Compliance requires supply chain attack detection
- ✅ Testing in security research environments
- ✅ Your threat model includes sophisticated adversaries

### How to enable Block D

#### Option 1: Environment Variable (Recommended)

```bash
# Windows (PowerShell)
$env:MCP_VERIFY_ENABLE_BLOCK_D="true"
mcp-verify validate <target>

# Linux/macOS
export MCP_VERIFY_ENABLE_BLOCK_D=true
mcp-verify validate <target>
```

#### Option 2: Security Profile

```bash
# Use the 'aggressive' profile which includes Block D
mcp-verify validate <target> --profile aggressive
```

#### Option 3: Configuration File

```json
{
  "security": {
    "enabledBlocks": ["OWASP", "MCP", "A", "B", "C", "D"]
  }
}
```

---

## Running Security Tests

### Prerequisites

```bash
npm install
npm run build
```

### Run All Tests (May Take Several Minutes)

```bash
npm test -- tests/security/rules/ --runInBand
```

**Note**: Running all 60 tests at once may cause resource exhaustion on Windows. Consider running by block instead.

### Run Tests by Block (Recommended)

```bash
# Block OWASP (SEC-001 to SEC-013)
npm test -- tests/security/rules/sec-00*.spec.ts --runInBand
npm test -- tests/security/rules/sec-01[0-3]*.spec.ts --runInBand

# Block MCP (SEC-014 to SEC-021)
npm test -- tests/security/rules/sec-01[4-9]*.spec.ts --runInBand
npm test -- tests/security/rules/sec-02[0-1]*.spec.ts --runInBand

# Block A (SEC-022 to SEC-030)
npm test -- tests/security/rules/sec-02[2-9]*.spec.ts --runInBand
npm test -- tests/security/rules/sec-030*.spec.ts --runInBand

# Block B (SEC-031 to SEC-041)
npm test -- tests/security/rules/sec-03*.spec.ts --runInBand
npm test -- tests/security/rules/sec-04[0-1]*.spec.ts --runInBand

# Block C (SEC-042 to SEC-050)
npm test -- tests/security/rules/sec-04[2-9]*.spec.ts --runInBand
npm test -- tests/security/rules/sec-050*.spec.ts --runInBand

# Block D (SEC-051 to SEC-060) - REQUIRES EXPLICIT ENABLE
MCP_VERIFY_ENABLE_BLOCK_D=true npm test -- tests/security/rules/sec-05*.spec.ts --runInBand
MCP_VERIFY_ENABLE_BLOCK_D=true npm test -- tests/security/rules/sec-060*.spec.ts --runInBand
```

### Run Individual Test

```bash
npm test -- tests/security/rules/sec-001-auth-bypass.spec.ts --runInBand
```

---

## Test Structure

All security tests follow a standard pattern:

```typescript
describe("SEC-XXX: Rule Name", () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(
    __dirname,
    "../../__test-reports__/sec-xxx",
  );

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({
      profile: "vulnerable-profile",
      lang: "en",
      transport: "stdio",
      timeout: 30000,
    });
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();
    if (fs.existsSync(testReportDir)) {
      fs.rmSync(testReportDir, { recursive: true, force: true });
    }
  });

  it("should detect vulnerability (SEC-XXX)", async () => {
    const target = serverManager.getTarget();
    await runValidationAction(target, {
      output: testReportDir,
      format: "json",
      lang: "en",
      quiet: true,
      html: false,
    });

    const dateStr = new Date().toISOString().split("T")[0];
    const jsonReportPath = path.join(
      testReportDir,
      dateStr,
      "validate",
      "json",
      "en",
    );
    const reportFiles = fs
      .readdirSync(jsonReportPath)
      .filter((f) => f.startsWith("mcp-report-") && f.endsWith(".json"));
    const latestReport = reportFiles.sort().reverse()[0];
    const report = JSON.parse(
      fs.readFileSync(path.join(jsonReportPath, latestReport), "utf8"),
    );

    // Find by ruleCode (language-independent)
    const finding = report.security.findings.find(
      (f: any) => f.ruleCode === "SEC-XXX",
    );

    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical|medium|low/i);
    expect(finding.message).toBeDefined();
    expect(typeof finding.message).toBe("string");
    expect(finding.message.length).toBeGreaterThan(0);
  });
});
```

### Key Design Decisions

1. **Rule Code Detection**: Tests find vulnerabilities by `ruleCode` instead of message text to support localization
2. **Permissive Assertions**: Severity and message checks are flexible to accommodate rule improvements
3. **Isolated Reports**: Each test creates its own report directory to avoid conflicts
4. **Sequential Execution**: `--runInBand` flag prevents parallel execution issues on Windows

---

## Adding New Security Rules & Tests

### 1. Create the Rule

```typescript
// libs/core/domain/security/rules/your-rule.rule.ts
export class YourRule implements ISecurityRule {
  code = "SEC-XXX";
  name = "Your Rule Name";
  severity: "high" = "high";

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    // Your detection logic here
    return findings;
  }
}
```

### 2. Add Vulnerable Server Profile

```typescript
// tests/fixtures/vulnerable_servers/configurable-server.ts
'your-profile': [
  {
    name: 'vulnerable_tool',
    description: 'Description that triggers your rule keywords',
    inputSchema: {
      type: 'object',
      properties: {
        param: { type: 'string', description: 'Parameter description' }
      }
    }
  }
]
```

### 3. Create the Test

```typescript
// tests/security/rules/sec-xxx-your-rule.spec.ts
describe("SEC-XXX: Your Rule Name", () => {
  // Follow standard test pattern (see above)
});
```

### 4. Keyword Alignment

Ensure your rule's keywords match the server profile descriptions:

```typescript
// In your rule
private readonly KEYWORDS = ['vulnerable', 'insecure', 'dangerous'];

// In server profile description
description: 'Vulnerable operation without validation'  // Contains 'vulnerable' keyword
```

---

## Troubleshooting

### Test Returns `undefined` Finding

**Symptom**: `expect(finding).toBeDefined()` fails

**Possible Causes**:

1. Rule keywords don't match server profile description
2. Block is disabled (check if rule is in Block D)
3. Rule has bugs in detection logic

**Debug Steps**:

```typescript
// Add logging before the assertion
console.log("Total findings:", report.security.findings.length);
console.log(
  "All rule codes:",
  report.security.findings.map((f) => f.ruleCode),
);
console.log("Looking for:", "SEC-XXX");
```

### `exitCode: undefined` Error

**Symptom**: Test runs but doesn't capture exit code

**Solution**: Run tests in smaller blocks or add delays:

```typescript
afterAll(async () => {
  await serverManager.stop();
  await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait 2s
  // ... cleanup
});
```

### Block D Tests Fail

**Symptom**: All SEC-051 to SEC-060 tests fail with no findings

**Solution**: Enable Block D with environment variable:

```bash
MCP_VERIFY_ENABLE_BLOCK_D=true npm test -- tests/security/rules/sec-054-endpoint-hijack.spec.ts
```

### Resource Exhaustion on Windows

**Symptom**: Tests hang or timeout after 20-30 tests

**Solution**: Run tests by block instead of all at once (see "Run Tests by Block" section)

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: "20"

      - run: npm ci
      - run: npm run build

      # Run by blocks to avoid resource exhaustion
      - name: Test Block OWASP
        run: npm test -- tests/security/rules/sec-0{0,1}*.spec.ts --runInBand

      - name: Test Block MCP
        run: npm test -- tests/security/rules/sec-01[4-9]*.spec.ts --runInBand

      # ... other blocks

      # Block D requires explicit enable
      - name: Test Block D (Optional)
        env:
          MCP_VERIFY_ENABLE_BLOCK_D: true
        run: npm test -- tests/security/rules/sec-05*.spec.ts --runInBand
        continue-on-error: true # Don't fail pipeline on Block D
```

---

## Test Coverage

| Category           | Coverage | Notes                                                       |
| ------------------ | -------- | ----------------------------------------------------------- |
| **Static Rules**   | 58/60    | All rules except SEC-051, SEC-052 have full detection logic |
| **Test Files**     | 60/60    | All rules have corresponding test files                     |
| **Passing Tests**  | ~45%     | Some tests require keyword alignment or Block D enable      |
| **Critical Rules** | 100%     | SEC-001 to SEC-013 (OWASP) all pass                         |

---

## Contributing

When adding new security rules:

1. ✅ Implement detection logic in the rule file
2. ✅ Add server profile that triggers the rule
3. ✅ Create test following standard pattern
4. ✅ Ensure keywords align between rule and profile
5. ✅ Test both positive (vulnerable) and negative (safe) cases
6. ✅ Document rule behavior in comments
7. ✅ Update this guide if introducing new patterns

---

## References

- [Security Rules Documentation](./libs/core/domain/security/rules/)
- [Vulnerable Server Profiles](./tests/fixtures/vulnerable_servers/configurable-server.ts)
- [Jest Configuration](./jest.config.js)

---

**Last Updated**: 2026-04-02
**Maintained by**: FinkTech
