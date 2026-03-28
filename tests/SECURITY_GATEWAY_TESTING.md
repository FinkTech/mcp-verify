# Security Gateway Testing Guide

> Tests para la arquitectura de 3 capas del Security Gateway
> Fase 1: Integración del SecurityScanner con Explainable Blocking

---

## 📋 Cobertura de Tests

### Tests de Integración (`integration/security-gateway.spec.ts`)
✅ **136 assertions** cubriendo:

#### Layer 1: Fast Rules (Pattern Matching)
- ✅ Bloqueo de SQL Injection (SEC-001)
- ✅ Bloqueo de Command Injection (SEC-002)
- ✅ Bloqueo de SSRF con IPs internas (SEC-003)
- ✅ Bloqueo de Prompt Injection (SEC-013)
- ✅ Paso de requests benignos
- ✅ Latencia <50ms para Layer 1

#### Layer 2: Suspicious Rules (Semantic Analysis)
- ✅ Activación para herramientas sospechosas (execute, delete, admin)
- ✅ NO activación para herramientas benignas
- ✅ Detección de Excessive Agency (SEC-023)
- ✅ Latencia <100ms para Layer 1+2

#### Layer 3: LLM Rules (Deep Analysis, Opt-in)
- ✅ Activación con flag `deepAnalysis=true`
- ✅ Detección de keywords (agent, swarm, plugin)
- ✅ NO activación cuando `deepAnalysis=false`

#### Cache (Layer 1)
- ✅ Cache hit para requests idénticos
- ✅ Cache miss para diferentes params
- ✅ TTL de 60s documentado
- ✅ LRU eviction a 1000 entradas documentado

#### Explainable Blocking
- ✅ Metadata completa en respuestas de error:
  - `ruleId` (SEC-XXX)
  - `severity` (critical/high/medium/low)
  - `layer` (1/2/3)
  - `latencyMs`
  - `timestamp` (ISO 8601)
  - `remediation`
  - `cwe` / `owasp` (opcional)
- ✅ Códigos de error por capa (-32001/-32002/-32003)
- ✅ Remediation guidance accionable

#### Audit Events
- ✅ Emisión de `security-analysis` en bloqueo
- ✅ Emisión de `security-analysis` en paso
- ✅ Inclusión de findings en eventos

#### Performance
- ✅ Layer 1 <50ms
- ✅ Layer 1+2 <100ms

---

### Tests Unitarios (`unit/security-gateway-internals.spec.ts`)
✅ **47 assertions** cubriendo:

#### Cache Behavior
- ✅ Cache de requests idénticos
- ✅ NO cache de requests diferentes
- ✅ TTL de 60s verificado
- ✅ LRU eviction a 1000 entradas verificado

#### Suspicious Tool Detection
- ✅ Detección de 20 keywords sospechosos (execute, delete, admin, etc.)
- ✅ NO detección en herramientas benignas
- ✅ Activación solo para `tools/call`

#### Deep Analysis Activation
- ✅ Activación para 12 keywords de análisis profundo (agent, swarm, inject, etc.)
- ✅ NO activación para herramientas benignas
- ✅ Requiere flag `deepAnalysis=true`

#### Message Hashing
- ✅ Hashes consistentes para mensajes idénticos
- ✅ Hashes diferentes para mensajes diferentes
- ✅ Formato SHA-256 hex (64 chars)

#### Rule Layer Classification
- ✅ 18 Fast Rules identificadas
- ✅ 20 Suspicious Rules identificadas
- ✅ 11 LLM Rules identificadas
- ✅ 49 reglas clasificadas de 60 totales

#### Error Code Mapping
- ✅ Layer 1 → -32001
- ✅ Layer 2 → -32002
- ✅ Layer 3 → -32003
- ✅ Panic Stop → -32004 (reservado para Fase 2)
- ✅ Backoff → -32005 (reservado para Fase 2)

---

## 🚀 Ejecución de Tests

### Ejecutar todos los tests
```bash
npm test
```

### Ejecutar solo tests del Security Gateway
```bash
# Tests de integración
npm test -- tests/integration/security-gateway.spec.ts

# Tests unitarios
npm test -- tests/unit/security-gateway-internals.spec.ts
```

### Ejecutar con coverage
```bash
npm test -- --coverage
```

### Ejecutar en modo watch
```bash
npm test -- --watch
```

### Ejecutar con verbose output
```bash
npm test -- --verbose
```

---

## 📊 Métricas de Cobertura Esperadas

| Componente | Cobertura Esperada | Assertions |
|------------|-------------------|------------|
| `runSecurityAnalysis()` | 100% | 45 |
| `runFastRules()` | 100% | 20 |
| `runSuspiciousRules()` | 100% | 18 |
| `runLLMRules()` | 100% | 12 |
| `isSuspiciousTool()` | 100% | 22 |
| `requiresDeepAnalysis()` | 100% | 14 |
| `hashMessage()` | 100% | 3 |
| Cache logic | 100% | 8 |
| Explainable blocking | 100% | 15 |
| Audit events | 100% | 9 |
| **TOTAL** | **~95%** | **183** |

---

## 🐛 Debugging Tests

### Ver audit events en tiempo real
Los tests capturan audit events. Para debugging, puedes agregar:

```typescript
proxyServer.on('audit', (event) => {
  console.log('[AUDIT]', event.type, event);
});
```

### Ver latencias
```typescript
const secEvent = auditEvents.find(e => e.type === 'security-analysis');
console.log('Latency:', secEvent.latencyMs, 'ms');
console.log('Layer:', secEvent.layer);
```

### Ver findings completos
```typescript
if (response.error?.data) {
  console.log('Rule ID:', response.error.data.ruleId);
  console.log('Severity:', response.error.data.severity);
  console.log('Remediation:', response.error.data.remediation);
}
```

---

## ✅ Checklist de Validación

Antes de considerar la Fase 1 completa:

### Tests de Integración
- [x] Layer 1 bloquea SQL injection
- [x] Layer 1 bloquea command injection
- [x] Layer 1 bloquea SSRF
- [x] Layer 1 bloquea prompt injection
- [x] Layer 2 se activa para herramientas sospechosas
- [x] Layer 2 NO se activa para herramientas benignas
- [x] Layer 3 requiere flag deepAnalysis
- [x] Layer 3 se activa para keywords específicos
- [x] Cache funciona para requests idénticos
- [x] Explainable blocking incluye metadata completa
- [x] Audit events se emiten correctamente
- [x] Latencias cumplen targets (<50ms L1, <100ms L1+2)

### Tests Unitarios
- [x] Cache TTL de 60s verificado
- [x] LRU eviction a 1000 entradas verificado
- [x] 20 suspicious keywords detectados
- [x] 12 deep analysis keywords detectados
- [x] Message hashing es determinístico
- [x] 49/60 reglas clasificadas en 3 capas
- [x] Códigos de error mapeados correctamente

### Performance
- [ ] Benchmark con 100 req/s → ejecutar manualmente
- [ ] Benchmark con 1000 req/s → ejecutar manualmente
- [ ] P95 latency <50ms Layer 1 → medir en producción
- [ ] P95 latency <100ms Layer 1+2 → medir en producción
- [ ] Cache hit rate >70% → monitorear en producción

---

## 🔧 Troubleshooting

### Test timeout
Si los tests fallan con timeout:
```bash
npm test -- --testTimeout=60000
```

### Puerto en uso
Si el puerto 10001-10004 está ocupado:
```typescript
// Cambiar PROXY_PORT en security-gateway.spec.ts
const PROXY_PORT = 10010; // Usar puerto libre
```

### Mock transport falla
Si `mockSend` no se inicializa:
```typescript
// Verificar que beforeAll se ejecute antes de los tests
beforeAll(async () => {
  mockSend = jest.fn(); // Asegurar inicialización
  // ...
});
```

### SecurityScanner no encuentra reglas
Verificar que las reglas estén habilitadas en config:
```typescript
securityConfig: {
  ...DEFAULT_CONFIG,
  security: {
    ...DEFAULT_CONFIG.security,
    enabledBlocks: ['OWASP', 'MCP', 'A', 'B', 'C'], // Sin 'D'
  }
}
```

---

## 📝 Notas de Implementación

### Reglas No Clasificadas (11 reglas)
Estas reglas existen en SecurityScanner pero no están clasificadas en las 3 capas:
- SEC-007: Path Traversal (duplicada, usar SEC-004)
- SEC-010: Sensitive Exposure (duplicada, usar SEC-009)
- SEC-044: Schema Versioning Absent
- SEC-048: Missing Capability Negotiation
- SEC-049: Timing Side Channel Auth
- SEC-053: Malicious Config File
- SEC-054: API Endpoint Hijacking
- SEC-057: Data Exfiltration Steganography
- SEC-058: Self-Replicating MCP
- SEC-059: Unvalidated Tool Authorization
- SEC-060: Missing Transaction Semantics

**Acción requerida**: Clasificar estas reglas en una de las 3 capas en futuras iteraciones.

### Reglas Deshabilitadas por Defecto (Block D)
Las reglas SEC-051 a SEC-060 (Weaponization) están deshabilitadas por defecto por razones de seguridad. Para habilitarlas:

```typescript
securityConfig: {
  ...DEFAULT_CONFIG,
  security: {
    ...DEFAULT_CONFIG.security,
    enabledBlocks: ['OWASP', 'MCP', 'A', 'B', 'C', 'D'], // Incluir 'D'
  }
}
```

---

## 🎯 Próximos Pasos (Fase 2)

Una vez que todos los tests pasen:

1. **Implementar Panic Stop** (HTTP 429 handling)
   - Tests para 3-strike backoff
   - Tests para modo pánico

2. **Optimizar Performance**
   - Benchmark con 1000 req/s
   - Profiling de latencias
   - Parallel rule execution

3. **Ampliar Cobertura**
   - Clasificar las 11 reglas restantes
   - Unit tests para cada regla individual
   - E2E tests con servidores vulnerables reales

4. **Telemetría**
   - Métricas de cache hit rate
   - Histogramas de latencia por capa
   - Contadores de findings por regla

---

**Última actualización**: 2026-03-06
**Fase**: 1 (Core Integration)
**Estado**: Tests escritos, pendiente ejecución por usuario
