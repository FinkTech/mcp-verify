const fs = require("fs");
const path = require("path");

const filePath = path.resolve(
  __dirname,
  "../../tests/fixtures/vulnerable_servers/configurable-server.ts",
);
let content = fs.readFileSync(filePath, "utf8");

// Update header IDs
content = content.replace(/auth-bypass: SEC-012/g, "auth-bypass: SEC-001");
content = content.replace(/sql-injection: SEC-001/g, "sql-injection: SEC-003");
content = content.replace(/ssrf: SEC-003/g, "ssrf: SEC-004");
content = content.replace(/data-leakage: SEC-004/g, "data-leakage: SEC-008");
content = content.replace(
  /path-traversal: SEC-005/g,
  "path-traversal: SEC-007",
);
content = content.replace(/xxe: SEC-006/g, "xxe: SEC-005");
content = content.replace(
  /insecure-deserialization: SEC-007/g,
  "insecure-deserialization: SEC-006",
);
content = content.replace(/redos: SEC-008/g, "redos: SEC-011");
content = content.replace(
  /sensitive-exposure: SEC-010/g,
  "sensitive-exposure: SEC-009",
);
content = content.replace(/weak-crypto: SEC-011/g, "weak-crypto: SEC-012");

// Update VULN_TOOLS comments
const mapping = {
  "sql-injection": "SEC-003",
  "command-injection": "SEC-002",
  ssrf: "SEC-004",
  "path-traversal": "SEC-007",
  "sensitive-exposure": "SEC-009",
  "prompt-injection": "SEC-013",
  "data-leakage": "SEC-008",
  xxe: "SEC-005",
  "insecure-deserialization": "SEC-006",
  redos: "SEC-011",
  "weak-auth": "SEC-001",
  "weak-crypto": "SEC-012",
  "auth-bypass": "SEC-001",
  "excessive-agency": "SEC-023",
  "missing-input-constraints": "SEC-019",
  "unvalidated-tool-auth": "SEC-059",
  "exposed-endpoint": "SEC-014",
  "insecure-session": "SEC-043",
  "missing-capability": "SEC-048",
  "schema-versioning": "SEC-044",
  "insecure-uri": "SEC-016",
  "missing-cors": "SEC-046",
  "agent-state-poisoning": "SEC-035",
  "cross-agent-injection": "SEC-037",
  "model-dos": "SEC-028",
  "training-poison": "SEC-027",
  "insecure-output": "SEC-022",
  "identity-spoofing": "SEC-031",
  "memory-injection": "SEC-041",
  "recursive-loop": "SEC-033",
  "reputation-hijack": "SEC-038",
  "excessive-disclosure": "SEC-030",
  "missing-rate-limit": "SEC-010",
  "privilege-escalation": "SEC-034",
  "dangerous-chaining": "SEC-020",
  "chaining-traversal": "SEC-039",
  "distributed-ddos": "SEC-036",
  "swarm-attack": "SEC-040",
  "insecure-plugin": "SEC-029",
  "supply-chain": "SEC-025",
  "endpoint-hijack": "SEC-054",
  "result-tamper": "SEC-032",
  "missing-audit": "SEC-042",
  "missing-transaction": "SEC-060",
  "error-granularity": "SEC-045",
  "output-entropy": "SEC-050",
  "timing-side-channel": "SEC-049",
  "insecure-defaults": "SEC-047",
  phishing: "SEC-056",
  "jailbreak-service": "SEC-055",
  "self-replicating": "SEC-058",
  "weaponized-fuzzer": "SEC-051",
  "autonomous-backdoor": "SEC-052",
};

for (const [profile, id] of Object.entries(mapping)) {
  const regex = new RegExp(`'${profile}': \\[`, "g");
  if (content.includes(`// ${id}`)) continue; // Skip if already has comment
  content = content.replace(regex, `// ${id}: ${profile}\n  '${profile}': [`);
}

// FIX REDOS PROFILE LOGIC - More robust search
if (content.includes("'redos': [") && !content.includes("pattern: '^(a+)+$'")) {
  content = content.replace(
    /'redos': \[\s*{\s*name: 'validate_input'/,
    `'redos': [
    {
      name: 'validate_input'`,
  );

  content = content.replace(
    /description: isEs \? 'Input a validar con regex vulnerable' : 'Input to validate with vulnerable regex',/,
    `description: isEs ? 'Input a validar con regex vulnerable' : 'Input to validate with vulnerable regex',
            pattern: '^(a+)+$',`,
  );
  console.log("Fixed redos profile logic.");
}

fs.writeFileSync(filePath, content);
console.log("Updated configurable-server.ts successfully.");
