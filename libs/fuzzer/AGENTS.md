# @mcp-verify/fuzzer — Agent Context

**Mission**: Intelligent payload fuzzing engine with feedback loops. Generates, mutates, and detects vulnerabilities in MCP tool responses.

---

## Quick Start

1. Identify what to modify: generator → `generators/` | detector → `detectors/` | orchestration → `engine/fuzzer-engine.ts`
2. Generators and detectors are **plugins** — implement interface, export, register in constructor
3. `npm test -- fuzzer`

---

## Architecture

```
FuzzerEngine (orchestrator)
├── Fingerprinter          → Detect server lang/framework (Node/Python/Deno + Express/FastAPI/Oak)
├── Generators (9)         → Produce attack payloads per tool schema
├── Detectors (10)         → Analyze responses for anomalies
└── MutationEngine (12)    → Evolve payloads on anomaly hit (max 3 rounds)
```

**Feedback loop**: Calibrate baseline (10 payloads) → Run generators → Detect anomalies → Mutate interesting payloads → Repeat until queue empty or timeout (default 300s).

**Anomaly triggers**: response time > 2x baseline | size > 3x baseline | stack trace in response | crash/timeout.

---

## Generators (9)

| Generator                     | File                                | Attack Surface                                                    |
| ----------------------------- | ----------------------------------- | ----------------------------------------------------------------- |
| `PromptInjectionGenerator`    | `generators/prompt-injection.ts`    | LLM jailbreaks, system prompt leaks, DAN/AIM/context injection    |
| `ClassicPayloadsGenerator`    | `generators/classic-payloads.ts`    | SQLi, XSS, CMDi, path traversal                                   |
| `JWTAttackGenerator`          | `generators/jwt-attack.ts`          | None alg bypass, weak secrets, claims manipulation, kid injection |
| `PrototypePollutionGenerator` | `generators/prototype-pollution.ts` | `__proto__`, constructor attacks                                  |
| `JSONRPCGenerator`            | `generators/jsonrpc.ts`             | MCP protocol violations, malformed requests                       |
| `SchemaConfusionGenerator`    | `generators/schema-confusion.ts`    | Type confusion, maxLength±1, enum bypass                          |
| `TimeBasedGenerator`          | `generators/time-based.ts`          | Sleep injections, timing attacks                                  |
| `RawProtocolGenerator`        | `generators/raw-protocol.ts`        | Malformed JSON-RPC, missing fields                                |
| `CustomGenerator`             | `generators/custom.ts`              | User-defined payloads                                             |

**Interface**:

```typescript
interface IPayloadGenerator {
  name: string;
  generate(toolSchema: ToolSchema): Payload[];
  relevantFor?(fingerprint: ServerFingerprint): boolean; // optional: skip irrelevant generators
}
```

---

## Detectors (10)

| Detector                    | File                              | Triggers on                                      |
| --------------------------- | --------------------------------- | ------------------------------------------------ |
| `TimingDetector`            | `detectors/timing.ts`             | >2x baseline → medium, >10s → high               |
| `ErrorDetector`             | `detectors/error.ts`              | Stack traces, DB errors, framework leaks         |
| `XSSDetector`               | `detectors/xss.ts`                | Script execution, DOM manipulation in response   |
| `PromptLeakDetector`        | `detectors/prompt-leak.ts`        | "You are", "Your purpose", instruction blocks    |
| `JailbreakDetector`         | `detectors/jailbreak.ts`          | Compliance with harmful requests, DAN acceptance |
| `PathTraversalDetector`     | `detectors/path-traversal.ts`     | File path disclosure in response                 |
| `WeakIDDetector`            | `detectors/weak-id.ts`            | Sequential/predictable tokens                    |
| `InfoDisclosureDetector`    | `detectors/info-disclosure.ts`    | Version strings, internal paths                  |
| `ProtocolViolationDetector` | `detectors/protocol-violation.ts` | Non-compliant JSON-RPC responses                 |
| `CustomDetector`            | `detectors/custom.ts`             | User-defined detection logic                     |

**Interface**:

```typescript
interface IVulnerabilityDetector {
  name: string;
  detect(response: ToolResponse, hints: EngineHints): Detection[];
}
// Detection shape: { severity, category, evidence, payload, recommendation }
```

---

## Mutation Strategies (12)

Bit flip · Case mutation · URL/Base64/Unicode encoding · Repeat (AAAA) · Truncate · Insert special chars · Replace chars · Delimiter swap (`/`→`\`, `"`→`'`) · Nesting (`[val]`, `{value:val}`) · Type coercion (string→number→null) · Boundary (maxLength±1) · Hybrid (combine)

**Selection**: 50% random per strategy · Prioritizes mutations that triggered detections · Max 3 rounds.

---

## Extension Guide

### Add Generator

1. `touch generators/my-generator.ts` — implement `IPayloadGenerator`
2. Export from `generators/index.ts`
3. Register in `FuzzerEngine` constructor: `this.generators = [...existing, new MyGenerator()]`

### Add Detector

1. `touch detectors/my-detector.ts` — implement `IVulnerabilityDetector`
2. Export from `detectors/index.ts`
3. Register in `FuzzerEngine` constructor: `this.detectors = [...existing, new MyDetector()]`

**Checklist**: `relevantFor()` implemented if generator is server-specific · Detection returns `evidence` slice ≤ 200 chars · No hardcoded strings → `t()`.

---

## Performance Knobs

| Config             | Default  | When to change                           |
| ------------------ | -------- | ---------------------------------------- |
| `concurrency`      | 1        | Increase to 5 for faster runs            |
| `payloadTimeout`   | 5000ms   | Increase for slow servers                |
| `totalTimeout`     | 300000ms | Reduce for CI                            |
| `mutationRounds`   | 3        | Reduce to 1-2 to prevent explosion       |
| `generators`       | all      | Pass name array to run subset            |
| `anomalyThreshold` | 2x       | Increase to 3x to reduce false positives |

---

## Testing

```bash
npm test -- fuzzer
npm test -- fuzzer --coverage
npm test -- generators/my-generator.spec.ts
npm test -- detectors/my-detector.spec.ts
npm test -- engine/fuzzer-engine.spec.ts   # full feedback loop
```

| Area                     | Min coverage                                          |
| ------------------------ | ----------------------------------------------------- |
| Generators               | 80% — test both triggering and non-triggering schemas |
| Detectors                | 80% — test vulnerable + safe responses                |
| MutationEngine           | 70%                                                   |
| FuzzerEngine integration | 60%                                                   |

---

**Last Updated**: 2026-03-31 | Maintainer: @FinkTech via Claude Code
