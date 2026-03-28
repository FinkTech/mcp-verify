# 🔌 Transport Layer Architecture - v0.1 vs v0.2+

## ⚠️ El Problema con v0.1

```typescript
// ❌ ACTUAL (MVP)
const eventSource = new EventSource(`${this.url}?message=...`);
```

**Problemas:**
- ❌ Abre nueva conexión SSE para cada petición
- ❌ No es un canal persistente
- ❌ Funciona solo con servidores "simples"
- ❌ Muchos servidores MCP requieren flujo bidireccional

---

## ✅ La Arquitectura Correcta (MCP Standard)

### Flujo Correcto: Canales Separados

```
┌─────────────────────────────────────────┐
│     MCP Client (mcp-verify)             │
└─────────────────────────────────────────┘
         ↓                    ↑
    [1] GET /sse         [3] SSE Message
         ↓                    ↑
    ┌─────────────────────────────────────┐
    │  MCP Server                         │
    │  (Persistent SSE channel)           │
    └─────────────────────────────────────┘
         ↑                    ↓
    [2] POST /messages   [4] Response
         ↓                    ↑
┌─────────────────────────────────────────┐
│     Response Handler                    │
└─────────────────────────────────────────┘
```

### Secuencia Correcta

```typescript
// Step 1: Abre canal persistente SSE
const eventSource = new EventSource(`${this.url}/sse`);

// Step 2: Configura listener para respuestas
eventSource.onmessage = (event) => {
  const response = JSON.parse(event.data);
  // Busca por ID para matchear con request pendiente
  const pending = this.pendingRequests.get(response.id);
  if (pending) {
    pending.resolve(response);
    this.pendingRequests.delete(response.id);
  }
};

// Step 3: Envía peticiones vía POST separado
async sendJsonRPC(method: string, params: any) {
  const message = {
    jsonrpc: '2.0',
    id: this.requestId++,
    method,
    params
  };
  
  // POST a endpoint de escritura
  await fetch(`${this.url}/messages`, {
    method: 'POST',
    body: JSON.stringify(message)
  });
  
  // Espera respuesta por canal SSE
  return await this.waitForResponse(message.id);
}

// Step 4: Cleanup
eventSource.close();
```

---

## 📊 Comparación: v0.1 vs v0.2+

| Aspecto | v0.1 (MVP) | v0.2+ (Production) |
|---------|-----------|-------------------|
| **Conexiones SSE** | Nueva por request | 1 persistente |
| **Canal de escritura** | URL params GET | POST separado |
| **Overhead** | Alto | Bajo |
| **Compatibilidad** | Servidores simples | Todos los MCP |
| **Request correlation** | Por timeout | Por ID matching |
| **Error handling** | Básico | Robusto |

---

## 🏗️ Arquitectura Recomendada (v0.2+)

### TransportLayer (Interfaz)

```typescript
interface TransportLayer {
  initialize(): Promise<void>;
  sendJsonRPC(method: string, params: any): Promise<any>;
  close(): Promise<void>;
}
```

### SSETransport (Implementación v0.2+)

```typescript
class SSETransport implements TransportLayer {
  private url: string;
  private eventSource: EventSource | null = null;
  private pendingRequests: Map<number, PendingRequest> = new Map();
  private requestId: number = 0;

  async initialize() {
    // Step 1: Abre canal persistente
    this.eventSource = new EventSource(`${this.url}/sse`);
    
    // Step 2: Configura listener
    this.eventSource.onmessage = (event) => {
      const response = JSON.parse(event.data);
      this.handleResponse(response);
    };
    
    // Step 3: Espera handshake completo
    await this.waitForInitialize();
  }

  async sendJsonRPC(method: string, params: any): Promise<any> {
    const id = ++this.requestId;
    
    const message = {
      jsonrpc: '2.0',
      id,
      method,
      params
    };

    // Envía vía POST
    await fetch(`${this.url}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });

    // Espera respuesta por canal SSE
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Timeout for method: ${method}`));
      }, 5000);

      this.pendingRequests.set(id, { resolve, reject, timeout });
    });
  }

  private handleResponse(response: any) {
    const pending = this.pendingRequests.get(response.id);
    if (pending) {
      clearTimeout(pending.timeout);
      if (response.error) {
        pending.reject(new Error(response.error.message));
      } else {
        pending.resolve(response.result);
      }
      this.pendingRequests.delete(response.id);
    }
  }

  async close() {
    if (this.eventSource) {
      this.eventSource.close();
    }
    // Rechaza requests pendientes
    for (const [id, pending] of this.pendingRequests) {
      pending.reject(new Error('Transport closed'));
    }
    this.pendingRequests.clear();
  }
}
```

---
}
```

---

## 🎯 Decisión Para v0.1

### ✅ MANTENER SIMPLE (MVP)
```typescript
// Funciona "suficientemente bien" para v0.1
// Si el servidor responde, validamos
// Si no responde, fallamos gracefully
```

### ❌ NO HACER (Premature Optimization)
```typescript
// No implementar full transport layer ahora
// Complejidad innecesaria para MVP
// Mejor esperar a tener casos de uso reales
```

---

## 📝 Actualización a validator.ts (COMENTARIO)

Agregá este comentario al código:

```typescript
/**
 * NOTA: Implementación MVP
 * 
 * v0.1 abre una nueva conexión SSE por cada petición.
 * Esto funciona contra servidores simples pero no es production-grade.
 * 
 * v0.2+ necesitará:
 * - Canal SSE persistente (GET /sse)
 * - Escritura vía POST separado (POST /messages)
 * - Correlation de requests por ID
 * - TransportLayer abstraction para soportar múltiples transportes
 * 
 * Por ahora, MVP es suficiente. Mejoramos cuando tengamos
 * feedback real de la comunidad.
 */
class MCPValidator {
  // ... código
}
```

---

## 🧪 Testing de Transportes (v0.2)

Cuando implementes transporte robusto:

```typescript
// Debería pasar todos estos tests
describe('SSETransport', () => {
  it('maintains persistent connection', async () => {
    const transport = new SSETransport(url);
    await transport.initialize();
    
    // Múltiples requests reutilizan misma conexión
    await transport.sendJsonRPC('tools/list', {});
    await transport.sendJsonRPC('resources/list', {});
    
    // Verifica que solo 1 SSE connection está abierta
    expect(connectionCount).toBe(1);
  });

  it('correlates responses by ID', async () => {
    // Request 1 se envía
    const p1 = transport.sendJsonRPC('initialize', {});
    
    // Request 2 se envía ANTES de que responda request 1
    const p2 = transport.sendJsonRPC('tools/list', {});
    
    // Ambas deberían resolverse correctamente
    const [r1, r2] = await Promise.all([p1, p2]);
    
    expect(r1.protocolVersion).toBeDefined();
    expect(r2.tools).toBeDefined();
  });

  it('handles server errors gracefully', async () => {
    const response = transport.sendJsonRPC('invalid/method', {});
    
    await expect(response).rejects.toThrow('Unknown method');
  });
});
```

---

## 💡 Conclusión

### v0.1: MVP Pragmático
- ✅ Funciona contra servidores simples
- ✅ Suficientemente rápido para validar idea
- ✅ Código simple, debuggeable

### v0.2+: Production Ready
- ✅ Transporte robusto
- ✅ Canales persistentes
- ✅ Compatible con todos los MCP servers
- ✅ Enterprise-grade

**No es deuda técnica si sabemos exactamente qué mejorar en v0.2.**

---

**Status:** 🟡 CONOCIDO, ACEPTABLE PARA MVP  
**Acción:** Documentar en código + planificar v0.2  
**Prioridad:** BAJA para v0.1, ALTA para v0.2
