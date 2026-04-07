/**
 * Fix Test IDs script
 * Maps test files to correct SEC IDs based on the rule source code.
 */
const fs = require("fs");
const path = require("path");

const TEST_DIR = path.resolve(__dirname, "../../tests/security/rules");

// Mapping based on suffixes found in test filenames
const suffixToId = {
  "auth-bypass": "SEC-001",
  "command-injection": "SEC-002",
  "sql-injection": "SEC-003",
  ssrf: "SEC-004",
  xxe: "SEC-005",
  "insecure-deserialization": "SEC-006",
  "path-traversal": "SEC-007",
  "data-leakage": "SEC-008",
  "sensitive-exposure": "SEC-009",
  "missing-rate-limiting": "SEC-010",
  redos: "SEC-011",
  "weak-crypto": "SEC-012",
  "prompt-injection": "SEC-013",
  "exposed-endpoint": "SEC-014",
  "missing-authentication": "SEC-015",
  "insecure-uri": "SEC-016",
  "excessive-permissions": "SEC-017",
  "secrets-in-descriptions": "SEC-018",
  "missing-input-constraints": "SEC-019",
  "dangerous-tool-chaining": "SEC-020",
  "unencrypted-credentials": "SEC-021",
  "insecure-output": "SEC-022",
  "excessive-agency": "SEC-023",
  "prompt-injection-via-tools": "SEC-024",
  "supply-chain": "SEC-025",
  "sensitive-data-in-tool-responses": "SEC-026",
  "training-poison": "SEC-027",
  "model-dos": "SEC-028",
  "insecure-plugin": "SEC-029",
  "excessive-disclosure": "SEC-030",
  "identity-spoofing": "SEC-031",
  "result-tamper": "SEC-032",
  "recursive-loop": "SEC-033",
  "privilege-escalation": "SEC-034",
  "agent-state-poisoning": "SEC-035",
  "distributed-ddos": "SEC-036",
  "cross-agent-injection": "SEC-037",
  "reputation-hijack": "SEC-038",
  "chaining-traversal": "SEC-039",
  "swarm-attack": "SEC-040",
  "memory-injection": "SEC-041",
  "missing-audit": "SEC-042",
  "insecure-session": "SEC-043",
  "schema-versioning": "SEC-044",
  "error-granularity": "SEC-045",
  "missing-cors": "SEC-046",
  "insecure-defaults": "SEC-047",
  "missing-capability": "SEC-048",
  "timing-side-channel": "SEC-049",
  "output-entropy": "SEC-050",
  "weaponized-fuzzer": "SEC-051",
  "autonomous-backdoor": "SEC-052",
  "malicious-config-file": "SEC-053",
  "endpoint-hijack": "SEC-054",
  "jailbreak-service": "SEC-055",
  phishing: "SEC-056",
  "data-exfiltration-steganography": "SEC-057",
  "self-replicating": "SEC-058",
  "unvalidated-tool-auth": "SEC-059",
  "missing-transaction": "SEC-060",
};

const files = fs.readdirSync(TEST_DIR);

files.forEach((file) => {
  if (!file.endsWith(".spec.ts")) return;

  // Extract suffix: sec-XXX-SUFFIX.spec.ts
  const match = file.match(/^sec-\d+-(.+)\.spec\.ts$/);
  if (!match) return;

  const suffix = match[1];
  const oldIdMatch = file.match(/^(sec-\d+)/);
  const oldId = oldIdMatch ? oldIdMatch[1].toUpperCase() : "";

  const newId = suffixToId[suffix];
  if (!newId) {
    console.warn(`No mapping found for suffix: ${suffix} (${file})`);
    return;
  }

  const newIdLower = newId.toLowerCase();
  const oldIdLower = oldId.toLowerCase();
  const newFile = `${newIdLower}-${suffix}.spec.ts`;
  const oldFilePath = path.join(TEST_DIR, file);
  const newFilePath = path.join(TEST_DIR, newFile);

  console.log(`Processing ${file} -> ${newFile} (${newId})`);

  let content = fs.readFileSync(oldFilePath, "utf8");

  // Update content
  // 1. Describe block: 'SEC-XXX: ...'
  if (oldId) {
    content = content.replace(new RegExp(oldId, "g"), newId);
  }

  // 2. Report paths: 'sec-xxx'
  if (oldIdLower) {
    content = content.replace(new RegExp(oldIdLower, "g"), newIdLower);
  }

  // Write updated content
  fs.writeFileSync(oldFilePath, content);

  // Rename file if different
  if (file !== newFile) {
    if (fs.existsSync(newFilePath)) {
      console.warn(
        `Destination file already exists: ${newFile}. Deleting old one to avoid duplicates.`,
      );
      fs.unlinkSync(oldFilePath);
    } else {
      fs.renameSync(oldFilePath, newFilePath);
    }
  }
});

console.log("Done.");
