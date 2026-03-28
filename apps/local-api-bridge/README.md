# 🌉 Local API Bridge (PLANNED - Not Implemented)

> **Status**: 🚧 **Experimental / Future Feature**
> **Version**: v1.0 - This component is **NOT implemented**. Directory exists as placeholder.
> **Priority**: Post-launch feature based on user demand

---

## 📋 What is Local API Bridge?

A **local HTTP/WebSocket server** that bridges:
- **mcp-verify CLI** (validation engine) ↔️ **Web Dashboard** (visual UI)

This is **different** from the current MCP Proxy (`libs/core/use-cases/proxy/`):

| Component | Purpose | Ports | Status |
|-----------|---------|-------|--------|
| **MCP Proxy** | MCP→MCP security gateway | 8080 | ✅ v1.0 (implemented) |
| **Local API Bridge** | REST API for Web Dashboard | 3000 | ❌ Future (planned) |

---

## 🎯 Why Build This?

### Problem
- CLI tools are powerful but lack visual analysis
- JSON reports are hard to explore for teams
- No historical tracking or trend analysis
- Hard to share findings with non-technical stakeholders

### Solution
```
┌──────────────────────────────────────────────────┐
│  Developer opens: http://localhost:3000          │
│  ┌────────────────────────────────────────────┐  │
│  │  📊 Dashboard (React/Vue)                  │  │
│  │  • Start validation (button click)         │  │
│  │  • See live logs (streaming)               │  │
│  │  • Filter findings (interactive)           │  │
│  │  • Compare baselines (visual diff)         │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
                        │ HTTP REST + WebSocket
                        ▼
┌──────────────────────────────────────────────────┐
│  Local API Bridge (Express.js)                   │
│  • Spawns: mcp-verify validate <target>         │
│  • Streams: stdout → WebSocket → UI             │
│  • Serves: ./reportes/ as JSON API              │
└──────────────────────────────────────────────────┘
```

---

## 🏗️ Planned Architecture

### Components

```
apps/local-api-bridge/
├── src/
│   ├── server.ts              # Express.js app entry point
│   ├── controllers/
│   │   ├── validation.controller.ts    # POST /api/validate
│   │   ├── reports.controller.ts       # GET /api/reports
│   │   └── status.controller.ts        # GET /api/status/:id
│   ├── services/
│   │   ├── cli-executor.service.ts     # Spawns mcp-verify CLI
│   │   ├── report-reader.service.ts    # Reads ./reportes/
│   │   └── websocket.service.ts        # Manages WS connections
│   ├── middleware/
│   │   ├── cors.middleware.ts          # CORS for localhost:*
│   │   ├── rate-limit.middleware.ts    # Max 10 validations/min
│   │   └── csrf.middleware.ts          # CSRF protection
│   └── sockets/
│       └── validation-stream.socket.ts # Real-time log streaming
└── package.json
```

### Tech Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| **Runtime** | Node.js 18+ | Same as CLI (consistency) |
| **Server** | Express.js | Simple, battle-tested |
| **WebSockets** | `ws` library | Lightweight, fast |
| **File Watching** | `chokidar` | Detect new reports |
| **Process Spawning** | `child_process` | Run CLI subprocess |
| **Validation** | `zod` | Type-safe API schemas |
| **CORS** | `cors` middleware | Allow localhost:* only |

---

## 🔌 API Specification (Draft v1.1)

### REST Endpoints

#### 1. Start Validation
```http
POST /api/validate
Content-Type: application/json

{
  "target": "http://localhost:3000",
  "options": {
    "security": true,
    "sandbox": true,
    "lang": "en"
  }
}

Response 202 Accepted:
{
  "validationId": "val_1f3d2a9b",
  "status": "running",
  "websocketUrl": "ws://localhost:3000/stream/val_1f3d2a9b"
}
```

#### 2. Get Validation Status
```http
GET /api/validate/val_1f3d2a9b

Response 200 OK:
{
  "id": "val_1f3d2a9b",
  "status": "completed",  // "running" | "completed" | "failed"
  "progress": 1.0,
  "startedAt": "2026-02-03T10:30:00Z",
  "completedAt": "2026-02-03T10:30:45Z",
  "report": {
    "score": 85,
    "findings": 12,
    "path": "./reportes/json/2026-02-03_10-30-00.json"
  }
}
```

#### 3. List Historical Validations
```http
GET /api/validations?limit=50&status=completed

Response 200 OK:
{
  "validations": [
    {
      "id": "val_1f3d2a9b",
      "target": "http://localhost:3000",
      "score": 85,
      "timestamp": "2026-02-03T10:30:00Z",
      "duration": 45000
    }
  ],
  "total": 156,
  "page": 1,
  "limit": 50
}
```

#### 4. Get Full Report
```http
GET /api/reports/2026-02-03_10-30-00.json

Response 200 OK:
{
  "metadata": { ... },
  "summary": { ... },
  "security": {
    "criticalFindings": [ ... ]
  }
}
```

#### 5. Cancel Validation
```http
DELETE /api/validate/val_1f3d2a9b

Response 200 OK:
{
  "cancelled": true
}
```

### WebSocket Protocol

#### Client → Server
```json
// Subscribe to validation logs
{
  "type": "subscribe",
  "validationId": "val_1f3d2a9b"
}

// Unsubscribe
{
  "type": "unsubscribe",
  "validationId": "val_1f3d2a9b"
}
```

#### Server → Client
```json
// Log message
{
  "type": "log",
  "level": "info",
  "message": "Connecting to http://localhost:3000...",
  "timestamp": "2026-02-03T10:30:05.123Z"
}

// Progress update
{
  "type": "progress",
  "percent": 0.25,
  "stage": "discovery",
  "message": "Discovering capabilities..."
}

// Security finding (real-time)
{
  "type": "finding",
  "severity": "high",
  "rule": "command-injection",
  "tool": "execute_shell",
  "description": "Shell metacharacters detected"
}

// Validation completed
{
  "type": "complete",
  "validationId": "val_1f3d2a9b",
  "score": 85,
  "report": { ... }
}

// Error
{
  "type": "error",
  "message": "Connection timeout",
  "code": "ETIMEDOUT"
}
```

---

## 💻 Implementation Examples

### Example 1: Express.js Server

```typescript
// src/server.ts
import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { validationRouter } from './controllers/validation.controller';
import { reportsRouter } from './controllers/reports.controller';

const app = express();
const wss = new WebSocketServer({ port: 3001 });

// Middleware
app.use(cors({ origin: ['http://localhost:3000', 'http://127.0.0.1:3000'] }));
app.use(express.json());

// Routes
app.use('/api/validate', validationRouter);
app.use('/api/reports', reportsRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.1.0' });
});

// Start server
app.listen(3000, () => {
  console.log('Local API Bridge running on http://localhost:3000');
});

// WebSocket handler
wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');

  ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.type === 'subscribe') {
      // Attach to validation stream
      ValidationStreamService.subscribe(msg.validationId, ws);
    }
  });
});
```

### Example 2: CLI Executor Service

```typescript
// src/services/cli-executor.service.ts
import { spawn } from 'child_process';
import { v4 as uuidv4 } from 'uuid';

export class CLIExecutorService {
  private activeValidations = new Map<string, ChildProcess>();

  async startValidation(target: string, options: any): Promise<string> {
    const validationId = `val_${uuidv4().split('-')[0]}`;

    // Build CLI command
    const args = ['validate', target, '--json'];
    if (options.security) args.push('--security');
    if (options.sandbox) args.push('--sandbox');
    if (options.lang) args.push('--lang', options.lang);

    // Spawn CLI process
    const proc = spawn('mcp-verify', args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    // Stream stdout to WebSocket
    proc.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          WebSocketService.broadcast(validationId, {
            type: 'log',
            level: 'info',
            message: line,
            timestamp: new Date().toISOString()
          });
        }
      }
    });

    // Handle stderr
    proc.stderr.on('data', (data) => {
      WebSocketService.broadcast(validationId, {
        type: 'log',
        level: 'error',
        message: data.toString(),
        timestamp: new Date().toISOString()
      });
    });

    // Handle completion
    proc.on('exit', (code) => {
      this.activeValidations.delete(validationId);

      WebSocketService.broadcast(validationId, {
        type: 'complete',
        validationId,
        exitCode: code
      });
    });

    // Track process
    this.activeValidations.set(validationId, proc);

    return validationId;
  }

  cancelValidation(validationId: string): boolean {
    const proc = this.activeValidations.get(validationId);
    if (proc) {
      proc.kill('SIGTERM');
      this.activeValidations.delete(validationId);
      return true;
    }
    return false;
  }
}
```

### Example 3: Report Reader Service

```typescript
// src/services/report-reader.service.ts
import fs from 'fs';
import path from 'path';
import chokidar from 'chokidar';

export class ReportReaderService {
  private reportsDir = './reportes/json';
  private watcher: chokidar.FSWatcher | null = null;

  constructor() {
    this.startWatcher();
  }

  /**
   * Watch for new reports
   */
  private startWatcher() {
    this.watcher = chokidar.watch(this.reportsDir, {
      persistent: true,
      ignoreInitial: true
    });

    this.watcher.on('add', (filePath) => {
      console.log(`New report detected: ${filePath}`);
      // Could emit event to WebSocket clients
    });
  }

  /**
   * List all reports
   */
  listReports(options: { limit?: number; offset?: number } = {}): any[] {
    const files = fs.readdirSync(this.reportsDir)
      .filter(f => f.endsWith('.json'))
      .sort()
      .reverse();

    const { limit = 50, offset = 0 } = options;
    const paginated = files.slice(offset, offset + limit);

    return paginated.map(file => {
      const filePath = path.join(this.reportsDir, file);
      const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

      return {
        filename: file,
        target: content.metadata.target,
        score: content.summary.score,
        timestamp: content.metadata.timestamp,
        path: filePath
      };
    });
  }

  /**
   * Get specific report
   */
  getReport(filename: string): any {
    const filePath = path.join(this.reportsDir, filename);

    if (!fs.existsSync(filePath)) {
      throw new Error('Report not found');
    }

    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }
}
```

---

## 🔒 Security Considerations

### Threat Model

| Threat | Impact | Mitigation |
|--------|--------|------------|
| **CSRF Attack** | Malicious site triggers validations | CSRF tokens for state-changing ops |
| **XSS in Reports** | Injected scripts in server descriptions | Sanitize all HTML with DOMPurify |
| **Path Traversal** | Read arbitrary files via `/api/reports/../../etc/passwd` | Validate filenames, use `PathValidator` |
| **Command Injection** | Inject CLI args like `; rm -rf /` | Validate all inputs with Zod schemas |
| **DoS via Mass Validations** | Spawn 1000 CLI processes | Rate limit: 10 validations/min |
| **SSRF** | Bridge validates attacker-controlled URLs | Already handled by CLI's URLValidator |
| **Unauth Access** | No authentication on API | Bind to localhost only (no remote access) |

### Security Implementation

#### 1. CSRF Protection
```typescript
// src/middleware/csrf.middleware.ts
import csurf from 'csurf';

export const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  }
});

// GET /api/csrf-token → { token: "abc123" }
// POST /api/validate requires X-CSRF-Token header
```

#### 2. Rate Limiting
```typescript
// src/middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';

export const validationRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 validations per minute
  message: 'Too many validation requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});
```

#### 3. Input Validation
```typescript
// src/schemas/validation.schema.ts
import { z } from 'zod';

export const ValidationRequestSchema = z.object({
  target: z.string()
    .url()
    .or(z.string().startsWith('npx '))
    .or(z.string().startsWith('node ')),
  options: z.object({
    security: z.boolean().optional(),
    sandbox: z.boolean().optional(),
    lang: z.enum(['en', 'es']).optional()
  }).optional()
});

// Usage in controller:
const parsed = ValidationRequestSchema.parse(req.body);
```

#### 4. Path Traversal Prevention
```typescript
// src/controllers/reports.controller.ts
import { PathValidator } from '../../../../libs/shared/utils/path-validator';

app.get('/api/reports/:filename', (req, res) => {
  const filename = req.params.filename;

  // Validate filename
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // Additional validation
  const safePath = PathValidator.validateOutputPath(filename, './reportes/json');
  const report = ReportReaderService.getReport(path.basename(safePath));

  res.json(report);
});
```

#### 5. CORS Restrictions
```typescript
// Only allow localhost origins
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://[::1]:3000'
    ];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
```

---

## 📊 Comparison: Current MCP Proxy vs Local API Bridge

| Feature        | MCP Proxy (v1.0)                              | Local API Bridge (Future)           |
|----------------|-----------------------------------------------|-------------------------------------|
| **Purpose**    | Security gateway for MCP servers              | REST API for Web Dashboard          |
| **Input**      | JSON-RPC (MCP protocol)                       | HTTP REST + WebSocket               |
| **Output**     | JSON-RPC (MCP protocol)                       | JSON + streaming logs               |
| **Clients**    | Claude Desktop, MCP clients                   | Web browsers (React/Vue)            |
| **Port**       | 8080                                          | 3000                                |
| **Security**   | Guardrails (PII, rate limit, etc.)            | CSRF, CORS, rate limit              |
| **Use Case**   | Runtime protection for untrusted servers      | Visual analysis & collaboration     |
| **Status**     | ✅ Implemented                                | ❌ Planned                          |

---

**IMPORTANT**: These are **complementary**, not replacements.

```
Web Dashboard → Local API Bridge → mcp-verify CLI → MCP Proxy → MCP Server
(UI)            (REST API)         (Validation)     (Security)   (Untrusted)
```

---

## 🤝 Contributing

Want to build this? Here's how:

1. **Discuss First**: Open GitHub Discussion with proposal
2. **Prototype**: Start with minimal Express + static HTML
3. **Security Review**: Get maintainer approval on CORS/CSRF
4. **PR**: Submit with tests + documentation

**Key Questions**:
- Should Bridge be bundled with CLI or separate npm package?
- Should it support remote access (not just localhost)?
- How to handle authentication for team features?

---

## 📚 References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (similar Web UI)
- [Postman Architecture](https://www.postman.com/product/architecture/) (local bridge pattern)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

## 📝 Decision Log

**2026-02-03**: Decision to postpone Local API Bridge
- **Rationale**: MCP Inspector already provides Web UI for MCP servers. Building a custom dashboard has unclear ROI. Better to focus on differentiating features (security analysis, Ollama support).
- **Alternative**: Users can use MCP Inspector + mcp-verify CLI separately
- **Revisit**: Q2 2026 if user demand increases

---

**Last Updated**: 2026-02-03
**Status**: Postponed to post-v1.0
**Maintainer**: FinkTech
