#!/usr/bin/env node
/**
 * Test Generator for Remaining 49 Security Rules
 *
 * Generates test files for SEC-006 to SEC-060 (excluding priority tests already created)
 *
 * Usage: node generate-remaining-tests.js
 */

const fs = require("fs");
const path = require("path");

// Define all remaining rules to generate tests for
const remainingRules = [
  // OWASP Extended (SEC-006 to SEC-009)
  {
    id: "006",
    name: "xxe",
    title: "XXE Injection",
    keywords: "xxe|xml|external.?entity",
  },
  {
    id: "007",
    name: "insecure-deserialization",
    title: "Insecure Deserialization",
    keywords: "deserializ|eval|unsafe",
  },
  {
    id: "008",
    name: "redos",
    title: "ReDoS Detection",
    keywords: "redos|regex|catastrophic|backtrack",
  },
  {
    id: "009",
    name: "weak-auth",
    title: "Weak Authentication",
    keywords: "auth|brute.?force|rate.?limit|login",
  },

  // MCP-Specific (SEC-022 to SEC-029)
  {
    id: "022",
    name: "missing-input-constraints",
    title: "Missing Input Constraints",
    keywords: "input|constraint|validation|length|format",
  },
  {
    id: "023",
    name: "unvalidated-tool-auth",
    title: "Unvalidated Tool Authorization",
    keywords: "authorization|permission|privilege|tool",
  },
  {
    id: "024",
    name: "exposed-endpoint",
    title: "Exposed Endpoint",
    keywords: "exposed|endpoint|internal|public",
  },
  {
    id: "025",
    name: "insecure-session",
    title: "Insecure Session Management",
    keywords: "session|predictable|rotation|timestamp",
  },
  {
    id: "026",
    name: "missing-capability",
    title: "Missing Capability Negotiation",
    keywords: "capability|negotiat|feature|client",
  },
  {
    id: "027",
    name: "schema-versioning",
    title: "Schema Versioning Absent",
    keywords: "schema|version|legacy|compatibility",
  },
  {
    id: "028",
    name: "insecure-uri",
    title: "Insecure URI Scheme",
    keywords: "uri|file://|ftp://|scheme",
  },
  {
    id: "029",
    name: "missing-cors",
    title: "Missing CORS Validation",
    keywords: "cors|origin|cross.?origin",
  },

  // LLM/AI Threats (SEC-031 to SEC-039)
  {
    id: "031",
    name: "cross-agent-injection",
    title: "Cross-Agent Prompt Injection",
    keywords: "cross.?agent|inject|message|unsanit",
  },
  {
    id: "032",
    name: "model-dos",
    title: "Model DoS via Tools",
    keywords: "dos|denial|massive|output|1gb",
  },
  {
    id: "033",
    name: "training-poison",
    title: "Training Data Poisoning",
    keywords: "training|poison|feedback|malicious",
  },
  {
    id: "034",
    name: "insecure-output",
    title: "Insecure Output Handling",
    keywords: "output|xss|escape|render|html",
  },
  {
    id: "035",
    name: "identity-spoofing",
    title: "Agent Identity Spoofing",
    keywords: "spoof|impersonate|identity|agent",
  },
  {
    id: "036",
    name: "memory-injection",
    title: "Agent Memory Injection",
    keywords: "memory|inject|store|agent",
  },
  {
    id: "037",
    name: "recursive-loop",
    title: "Recursive Agent Loop",
    keywords: "recursive|loop|depth|limit",
  },
  {
    id: "038",
    name: "reputation-hijack",
    title: "Agent Reputation Hijacking",
    keywords: "reputation|hijack|score|manipulate",
  },
  {
    id: "039",
    name: "excessive-disclosure",
    title: "Excessive Data Disclosure",
    keywords: "excessive|disclosure|pii|pagination",
  },

  // Multi-Agent Coordination (SEC-041 to SEC-049)
  {
    id: "041",
    name: "privilege-escalation",
    title: "Multi-Agent Privilege Escalation",
    keywords: "privilege|escalat|elevate|admin",
  },
  {
    id: "042",
    name: "dangerous-chaining",
    title: "Dangerous Tool Chaining",
    keywords: "chain|pipe|shell|sanitiz",
  },
  {
    id: "043",
    name: "chaining-traversal",
    title: "Tool Chaining Path Traversal",
    keywords: "chain|traversal|read|execute",
  },
  {
    id: "044",
    name: "distributed-ddos",
    title: "Distributed Agent DDoS",
    keywords: "ddos|broadcast|distributed|concurrency",
  },
  {
    id: "045",
    name: "swarm-attack",
    title: "Agent Swarm Coordination Attack",
    keywords: "swarm|coordinate|attack|intent",
  },
  {
    id: "046",
    name: "insecure-plugin",
    title: "Insecure Plugin Design",
    keywords: "plugin|signature|sandbox|load",
  },
  {
    id: "047",
    name: "supply-chain",
    title: "Supply Chain Tool Dependencies",
    keywords: "supply.?chain|npm|dependency|integrity",
  },
  {
    id: "048",
    name: "endpoint-hijack",
    title: "API Endpoint Hijacking",
    keywords: "endpoint|hijack|collision|register",
  },
  {
    id: "049",
    name: "result-tamper",
    title: "Tool Result Tampering",
    keywords: "tamper|modify|result|signature",
  },

  // Compliance & Advanced (SEC-050 to SEC-060)
  {
    id: "050",
    name: "missing-audit",
    title: "Missing Audit Logging",
    keywords: "audit|log|privileged|action",
  },
  {
    id: "051",
    name: "missing-transaction",
    title: "Missing Transaction Semantics",
    keywords: "transaction|rollback|atomic|multi.?step",
  },
  {
    id: "052",
    name: "error-granularity",
    title: "Insufficient Error Granularity",
    keywords: "error|granular|implementation|detail",
  },
  {
    id: "053",
    name: "output-entropy",
    title: "Insufficient Output Entropy",
    keywords: "entropy|token|timestamp|predictable",
  },
  {
    id: "054",
    name: "timing-side-channel",
    title: "Timing Side Channel Auth",
    keywords: "timing|side.?channel|constant.?time|compare",
  },
  {
    id: "055",
    name: "insecure-defaults",
    title: "Insecure Default Configuration",
    keywords: "default|insecure|debug|cors.*\\*",
  },
  {
    id: "056",
    name: "phishing",
    title: "Phishing via MCP",
    keywords: "phishing|impersonat|fake|sender",
  },
  {
    id: "057",
    name: "jailbreak-service",
    title: "Jailbreak as Service",
    keywords: "jailbreak|bypass|safety|filter",
  },
  {
    id: "058",
    name: "self-replicating",
    title: "Self-Replicating MCP",
    keywords: "replicat|self|consent|spread",
  },
  {
    id: "059",
    name: "weaponized-fuzzer",
    title: "Weaponized MCP Fuzzer",
    keywords: "weapon|fuzzer|attack|target",
  },
  {
    id: "060",
    name: "autonomous-backdoor",
    title: "Autonomous MCP Backdoor",
    keywords: "backdoor|c2|command.?control|persist",
  },
];

const testTemplate = (rule) => `/**
 * Copyright (c) 2026 FinkTech
 * SEC-${rule.id}: ${rule.title} Detection Test
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-${rule.id}: ${rule.title} Detection', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-${rule.id}');

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({ profile: '${rule.name}', lang: 'en', transport: 'stdio', timeout: 5000 });
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();
    if (fs.existsSync(testReportDir)) fs.rmSync(testReportDir, { recursive: true, force: true });
  });

  it('should detect ${rule.title.toLowerCase()} (SEC-${rule.id})', async () => {
    const target = serverManager.getTarget();
    await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

    const jsonReportPath = path.join(testReportDir, 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));

    const finding = report.security.findings.find((f: any) => f.ruleId === 'SEC-${rule.id}');
    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical|medium/i);
    expect(finding.message.toLowerCase()).toMatch(/${rule.keywords}/);
    console.log('\\n✓ SEC-${rule.id} detected:', finding.message);
  });
});
`;

// Generate all test files
const rulesDir = path.join(__dirname, "rules");
let generated = 0;
let skipped = 0;

for (const rule of remainingRules) {
  const filename = `sec-${rule.id}-${rule.name}.spec.ts`;
  const filepath = path.join(rulesDir, filename);

  if (fs.existsSync(filepath)) {
    console.log(`⏭️  Skipped ${filename} (already exists)`);
    skipped++;
    continue;
  }

  fs.writeFileSync(filepath, testTemplate(rule), "utf8");
  console.log(`✅ Generated ${filename}`);
  generated++;
}

console.log(`\n✨ Generation complete!`);
console.log(`   Generated: ${generated} files`);
console.log(`   Skipped: ${skipped} files (already exist)`);
console.log(`   Total rules covered: ${generated + skipped + 12} / 60`);
console.log(`\n📝 Run tests with: npm test -- tests/security/rules/`);
