# 📊 Web Dashboard (PLANNED - Not Implemented)

> **Status**: 🚧 **Experimental / Future Feature**
> **Version**: v1.0 - This component is **NOT implemented**. Directory exists as placeholder.
> **Priority**: Post-launch feature based on user demand

---

## 📋 What is Web Dashboard?

A **modern web interface** for visualizing MCP server validation results:

- **Interactive reports** instead of CLI JSON
- **Historical tracking** with trend analysis
- **Real-time validation** with live progress
- **Team collaboration** features (annotations, assignments)

This is the **frontend UI** that connects to the **Local API Bridge** (REST API).

```
┌─────────────────────────────────────────────────────────┐
│  http://localhost:3000                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  📊 mcp-verify Dashboard                          │  │
│  │                                                    │  │
│  │  ┌──────────────┬──────────────┬──────────────┐   │  │
│  │  │ 🔍 Validate  │ 📈 History   │ ⚙️ Settings  │   │  │
│  │  └──────────────┴──────────────┴──────────────┘   │  │
│  │                                                    │  │
│  │  🎯 Quick Validation                              │  │
│  │  ┌──────────────────────────────────────────┐     │  │
│  │  │ Target: http://localhost:8080            │     │  │
│  │  │ [✓] Security  [✓] Sandbox  [ ] Fuzzing  │     │  │
│  │  │                       [▶ Start Validation] │     │  │
│  │  └──────────────────────────────────────────┘     │  │
│  │                                                    │  │
│  │  📊 Live Progress (85%)                           │  │
│  │  ████████████████░░░░ Discovery complete          │  │
│  │  ████████████████████ Security scan running...    │  │
│  │                                                    │  │
│  │  🔴 Critical Findings (2)                         │  │
│  │  • Command Injection in execute_shell             │  │
│  │  • SQL Injection in db_query                      │  │
│  │                                                    │  │
│  │  🟡 High Findings (5)                             │  │
│  │  • Path Traversal in read_file                    │  │
│  │  • XSS in render_template                         │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Why Build This?

### Problem

- **JSON reports are hard to read**: Developers need visual tools
- **No historical tracking**: Can't see security score trends over time
- **Hard to share**: Non-technical stakeholders can't interpret CLI output
- **Manual workflow**: Copy-paste findings into JIRA/Notion

### Solution: Visual Dashboard

```
Developer's Workflow:
1. Open http://localhost:3000
2. Click "Start Validation"
3. Watch live progress (streaming logs)
4. See findings with visual severity badges
5. Filter by severity/category/tool
6. Compare with previous scans (baseline)
7. Export report or share link with team
```

---

## 🏗️ Planned Architecture

### Components

```
apps/web-dashboard/
├── public/
│   ├── index.html              # Entry point
│   ├── favicon.ico
│   └── assets/                 # Static images/icons
├── src/
│   ├── main.tsx                # React app entry point
│   ├── App.tsx                 # Root component
│   ├── pages/
│   │   ├── ValidationPage.tsx      # Main validation view
│   │   ├── HistoryPage.tsx         # Historical validations
│   │   ├── ReportDetailPage.tsx    # Detailed report view
│   │   └── SettingsPage.tsx        # User preferences
│   ├── components/
│   │   ├── ValidationForm.tsx      # Target input + options
│   │   ├── ProgressBar.tsx         # Live progress indicator
│   │   ├── FindingsList.tsx        # Security findings table
│   │   ├── FindingCard.tsx         # Single finding detail
│   │   ├── ScoreGauge.tsx          # Visual score (0-100)
│   │   ├── TrendChart.tsx          # Historical trend graph
│   │   └── LogStream.tsx           # Real-time log viewer
│   ├── services/
│   │   ├── api.service.ts          # HTTP client (REST API)
│   │   ├── websocket.service.ts    # WebSocket connection
│   │   └── report.service.ts       # Report data parsing
│   ├── hooks/
│   │   ├── useValidation.ts        # Validation state management
│   │   ├── useWebSocket.ts         # WebSocket connection hook
│   │   └── useReports.ts           # Historical reports hook
│   ├── store/
│   │   ├── validationStore.ts      # Zustand/Redux store
│   │   └── settingsStore.ts        # User preferences
│   ├── types/
│   │   ├── validation.types.ts     # TypeScript interfaces
│   │   └── report.types.ts         # Report data structures
│   └── styles/
│       ├── globals.css             # Global styles
│       └── theme.ts                # Theme configuration
├── package.json
├── vite.config.ts              # Vite configuration
├── tailwind.config.js          # Tailwind CSS
└── tsconfig.json               # TypeScript config
```

### Tech Stack

| Layer             | Technology           | Reason                              |
| ----------------- | -------------------- | ----------------------------------- |
| **Framework**     | React 18+            | Industry standard, large ecosystem  |
| **Build Tool**    | Vite                 | Fast dev server, modern bundling    |
| **Styling**       | Tailwind CSS         | Rapid UI development, consistency   |
| **Charts**        | Recharts             | React-native charting library       |
| **State**         | Zustand              | Lightweight, TypeScript-friendly    |
| **HTTP Client**   | Axios                | Interceptors, request cancellation  |
| **WebSocket**     | Native WebSocket API | No extra dependencies               |
| **UI Components** | shadcn/ui            | Accessible, customizable components |
| **Icons**         | Lucide React         | Modern icon set                     |
| **Routing**       | React Router v6      | Standard routing solution           |

---

## 🖥️ User Interface Mockups

### 1. Validation Page (Main View)

```
┌─────────────────────────────────────────────────────────────────┐
│ 🔍 mcp-verify Dashboard                    [Settings] [Help]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🎯 Start New Validation                                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Server Target:                                            │  │
│  │ ┌───────────────────────────────────────────────────┐     │  │
│  │ │ http://localhost:3000                             │     │  │
│  │ └───────────────────────────────────────────────────┘     │  │
│  │                                                            │  │
│  │ Options:                                                   │  │
│  │ [✓] Security Scan    [✓] Sandbox Mode    [ ] Fuzzing     │  │
│  │ [ ] Compliance       [ ] Quality         [✓] Performance  │  │
│  │                                                            │  │
│  │ Language: [English ▼]                [▶ Start Validation] │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  📊 Active Validation                                           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Target: http://localhost:3000         Duration: 00:45     │  │
│  │                                                            │  │
│  │ Progress: 85%                                              │  │
│  │ ████████████████████████████░░░░░                          │  │
│  │                                                            │  │
│  │ Stage: Security Scan                                       │  │
│  │ • Discovery complete (12 tools, 3 resources)              │  │
│  │ • Security scan in progress...                            │  │
│  │   - Analyzing tool: execute_command                       │  │
│  │   - Detected: 2 critical, 5 high, 3 medium findings      │  │
│  │                                                            │  │
│  │ [Pause] [Cancel]                        [View Live Logs ▶]│  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  🔴 Findings Summary                                            │
│  ┌─────────────┬──────┬────────────────────────────────────┐   │
│  │ Severity    │ Count│ Top Issues                         │   │
│  ├─────────────┼──────┼────────────────────────────────────┤   │
│  │ 🔴 Critical │   2  │ Command Injection, SQL Injection   │   │
│  │ 🟠 High     │   5  │ Path Traversal, XSS, SSRF          │   │
│  │ 🟡 Medium   │   8  │ Weak Crypto, Missing Rate Limits   │   │
│  │ 🔵 Low      │   3  │ Info Disclosure, Missing Headers   │   │
│  └─────────────┴──────┴────────────────────────────────────┘   │
│                                                                 │
│  Final Score: 72/100 (C)                  [View Full Report ▶] │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2. History Page

```
┌─────────────────────────────────────────────────────────────────┐
│ 📈 Validation History                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📊 Score Trend (Last 30 Days)                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ 100 │                                  ╱──╲                │  │
│  │  90 │                            ╱────╯    ╲               │  │
│  │  80 │                      ╱────╯            ╲──╲          │  │
│  │  70 │              ╱──────╯                      ╲         │  │
│  │  60 │        ╱────╯                               ●        │  │
│  │  50 │  ╱────╯                                     72       │  │
│  │   0 └────────────────────────────────────────────────────  │  │
│  │      Jan 20    Jan 25    Jan 30    Feb 4     Feb 9       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  📋 Recent Validations                       [Filter ▼] [Export]│
│  ┌─────────────────────────────────────────────────────────────┤
│  │ Date       │ Target              │ Score │ Findings │ Action│
│  ├────────────┼─────────────────────┼───────┼──────────┼───────┤
│  │ Feb 9 12:30│ localhost:3000      │  72   │   18     │ [View]│
│  │ Feb 8 15:45│ localhost:3000      │  78   │   12     │ [View]│
│  │ Feb 7 09:20│ production-server   │  65   │   25     │ [View]│
│  │ Feb 6 14:10│ localhost:3000      │  85   │    6     │ [View]│
│  │ Feb 5 10:05│ staging-server      │  70   │   15     │ [View]│
│  └────────────┴─────────────────────┴───────┴──────────┴───────┘
│                                                                 │
│  [1] [2] [3] ... [15]                     Showing 1-10 of 156  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Report Detail Page

```
┌─────────────────────────────────────────────────────────────────┐
│ 📄 Validation Report - Feb 9, 2026 12:30                        │
│ Target: http://localhost:3000                    Score: 72/100  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📊 Overview                              [⬇ Download JSON/SARIF]│
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Duration: 00:45                     Tools Analyzed: 12    │  │
│  │ Findings: 18                        Resources: 3          │  │
│  │                                                            │  │
│  │ Security Score Distribution:                               │  │
│  │ ┌─────────────┬────────┐                                  │  │
│  │ │ Protocol    │  100%  │ ████████████████████████████████ │  │
│  │ │ Transport   │   95%  │ ██████████████████████████████░  │  │
│  │ │ Tools       │   60%  │ ███████████████░░░░░░░░░░░░░░░░  │  │
│  │ │ Resources   │   85%  │ ████████████████████████░░░░░░░  │  │
│  │ └─────────────┴────────┘                                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  🔴 Critical Findings (2)                         [Filter ▼]    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │ 🔴 SEC-002: Command Injection                       │   │  │
│  │ │ Tool: execute_shell                                  │   │  │
│  │ │ Issue: No validation on command parameter           │   │  │
│  │ │ Risk: Arbitrary command execution                    │   │  │
│  │ │ Evidence: Accepts user input directly              │   │  │
│  │ │ [View Details] [Assign] [Mark False Positive]       │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  │                                                            │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │ 🔴 SEC-003: SQL Injection                           │   │  │
│  │ │ Tool: db_query                                       │   │  │
│  │ │ Issue: Dynamic SQL without parameterization         │   │  │
│  │ │ Risk: Database compromise                            │   │  │
│  │ │ Evidence: String concatenation in query             │   │  │
│  │ │ [View Details] [Assign] [Mark False Positive]       │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  🟠 High Findings (5)   🟡 Medium (8)   🔵 Low (3)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔌 API Integration

### Connection to Local API Bridge

```typescript
// src/services/api.service.ts
import axios from "axios";

const API_BASE_URL = "http://localhost:3000/api";

export class APIService {
  private client = axios.create({
    baseURL: API_BASE_URL,
    timeout: 60000,
    headers: { "Content-Type": "application/json" },
  });

  /**
   * Start a new validation
   */
  async startValidation(
    target: string,
    options: ValidationOptions,
  ): Promise<ValidationResponse> {
    const response = await this.client.post("/validate", {
      target,
      options,
    });

    return response.data;
  }

  /**
   * Get validation status
   */
  async getValidationStatus(validationId: string): Promise<ValidationStatus> {
    const response = await this.client.get(`/validate/${validationId}`);
    return response.data;
  }

  /**
   * List historical validations
   */
  async listValidations(params?: ListParams): Promise<ValidationList> {
    const response = await this.client.get("/validations", { params });
    return response.data;
  }

  /**
   * Get full report
   */
  async getReport(filename: string): Promise<Report> {
    const response = await this.client.get(`/reports/${filename}`);
    return response.data;
  }

  /**
   * Cancel validation
   */
  async cancelValidation(validationId: string): Promise<void> {
    await this.client.delete(`/validate/${validationId}`);
  }
}
```

### WebSocket Integration

```typescript
// src/services/websocket.service.ts
export class WebSocketService {
  private ws: WebSocket | null = null;
  private listeners = new Map<string, Function[]>();

  connect(validationId: string) {
    const wsUrl = `ws://localhost:3001/stream/${validationId}`;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log("WebSocket connected");
      this.emit("connected");
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);

      switch (message.type) {
        case "log":
          this.emit("log", message);
          break;
        case "progress":
          this.emit("progress", message);
          break;
        case "finding":
          this.emit("finding", message);
          break;
        case "complete":
          this.emit("complete", message);
          break;
        case "error":
          this.emit("error", message);
          break;
      }
    };

    this.ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      this.emit("error", error);
    };

    this.ws.onclose = () => {
      console.log("WebSocket disconnected");
      this.emit("disconnected");
    };
  }

  on(event: string, callback: Function) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  private emit(event: string, data?: any) {
    const callbacks = this.listeners.get(event) || [];
    callbacks.forEach((cb) => cb(data));
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}
```

---

## 💻 Component Examples

### 1. ValidationForm Component

```tsx
// src/components/ValidationForm.tsx
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";

export function ValidationForm({
  onSubmit,
}: {
  onSubmit: (data: ValidationData) => void;
}) {
  const [target, setTarget] = useState("http://localhost:3000");
  const [options, setOptions] = useState({
    security: true,
    sandbox: true,
    fuzzing: false,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ target, options });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4 p-6 border rounded-lg">
      <div>
        <label className="block text-sm font-medium mb-2">Server Target</label>
        <Input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="http://localhost:3000"
          required
        />
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium">Options</label>

        <div className="flex items-center space-x-2">
          <Checkbox
            id="security"
            checked={options.security}
            onCheckedChange={(checked) =>
              setOptions({ ...options, security: !!checked })
            }
          />
          <label htmlFor="security">Security Scan</label>
        </div>

        <div className="flex items-center space-x-2">
          <Checkbox
            id="sandbox"
            checked={options.sandbox}
            onCheckedChange={(checked) =>
              setOptions({ ...options, sandbox: !!checked })
            }
          />
          <label htmlFor="sandbox">Sandbox Mode</label>
        </div>

        <div className="flex items-center space-x-2">
          <Checkbox
            id="fuzzing"
            checked={options.fuzzing}
            onCheckedChange={(checked) =>
              setOptions({ ...options, fuzzing: !!checked })
            }
          />
          <label htmlFor="fuzzing">Fuzzing</label>
        </div>
      </div>

      <Button type="submit" className="w-full">
        ▶ Start Validation
      </Button>
    </form>
  );
}
```

### 2. ProgressBar Component

```tsx
// src/components/ProgressBar.tsx
export function ProgressBar({
  percent,
  stage,
  message,
}: {
  percent: number;
  stage: string;
  message: string;
}) {
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="font-medium">
          Progress: {Math.round(percent * 100)}%
        </span>
        <span className="text-gray-600">{stage}</span>
      </div>

      <div className="w-full bg-gray-200 rounded-full h-4 overflow-hidden">
        <div
          className="bg-blue-600 h-4 rounded-full transition-all duration-300"
          style={{ width: `${percent * 100}%` }}
        />
      </div>

      <p className="text-sm text-gray-600">{message}</p>
    </div>
  );
}
```

### 3. FindingCard Component

```tsx
// src/components/FindingCard.tsx
export function FindingCard({ finding }: { finding: SecurityFinding }) {
  const severityColors = {
    critical: "bg-red-100 border-red-500 text-red-900",
    high: "bg-orange-100 border-orange-500 text-orange-900",
    medium: "bg-yellow-100 border-yellow-500 text-yellow-900",
    low: "bg-blue-100 border-blue-500 text-blue-900",
  };

  const severityIcons = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🔵",
  };

  return (
    <div
      className={`border-l-4 p-4 rounded ${severityColors[finding.severity]}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h3 className="font-semibold text-lg">
            {severityIcons[finding.severity]} {finding.ruleCode}:{" "}
            {finding.message}
          </h3>
          <p className="text-sm mt-1">
            Tool:{" "}
            <code className="bg-white px-2 py-1 rounded">
              {finding.component}
            </code>
          </p>
          <p className="text-sm mt-2">
            {finding.evidence?.risk || "No additional details"}
          </p>
        </div>

        <div className="flex gap-2">
          <Button variant="outline" size="sm">
            View Details
          </Button>
          <Button variant="outline" size="sm">
            Assign
          </Button>
        </div>
      </div>

      {finding.remediation && (
        <div className="mt-3 p-3 bg-white rounded">
          <p className="text-xs font-medium">💡 Remediation:</p>
          <p className="text-xs mt-1">{finding.remediation}</p>
        </div>
      )}
    </div>
  );
}
```

### 4. TrendChart Component

```tsx
// src/components/TrendChart.tsx
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";

export function TrendChart({
  data,
}: {
  data: Array<{ date: string; score: number }>;
}) {
  return (
    <div className="p-6 border rounded-lg">
      <h3 className="text-lg font-semibold mb-4">
        📊 Score Trend (Last 30 Days)
      </h3>

      <LineChart width={800} height={300} data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="date" />
        <YAxis domain={[0, 100]} />
        <Tooltip />
        <Legend />
        <Line
          type="monotone"
          dataKey="score"
          stroke="#3b82f6"
          strokeWidth={2}
          dot={{ r: 4 }}
        />
      </LineChart>
    </div>
  );
}
```

---

## 🔒 Security Considerations

### Client-Side Security

| Threat                  | Mitigation                                                      |
| ----------------------- | --------------------------------------------------------------- |
| **XSS in Report Data**  | Sanitize all HTML with DOMPurify, use React's built-in escaping |
| **CSRF Attacks**        | Include CSRF token in all POST requests                         |
| **Insecure WebSocket**  | Validate message signatures, limit message size                 |
| **Sensitive Data Leak** | Never log API tokens, redact credentials in UI                  |
| **Open Redirects**      | Validate all URLs before navigation                             |

### Implementation

```typescript
// src/utils/sanitize.ts
import DOMPurify from "dompurify";

export function sanitizeHTML(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "code", "pre"],
    ALLOWED_ATTR: [],
  });
}

// src/utils/validation.ts
export function isValidURL(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}
```

---

## 🤝 Contributing

Want to build this? Here's how:

1. **Discuss First**: Open GitHub Discussion with UI/UX mockups
2. **Prototype**: Start with Vite + React + TailwindCSS
3. **Connect API**: Ensure Local API Bridge is running
4. **PR**: Submit with screenshots + demo video

**Key Questions**:

- Should dashboard be served by API Bridge or separate dev server?
- What chart library for historical trends?
- Dark mode by default or user preference?

---

## 📚 References

- [MCP Inspector](https://github.com/modelcontextprotocol/inspector) - Official MCP Web UI
- [React Best Practices 2024](https://react.dev/)
- [Vite Guide](https://vitejs.dev/guide/)
- [shadcn/ui Components](https://ui.shadcn.com/)
- [Recharts Documentation](https://recharts.org/)

---

## 📝 Decision Log

**2026-02-09**: Decision to postpone Web Dashboard

- **Rationale**: Local API Bridge must exist first. Building UI without backend has no value. Also, MCP Inspector already provides basic Web UI.
- **Alternative**: Users can use CLI + JSON reports + external tools (VS Code extensions, Jupyter notebooks)
- **Revisit**: Q2 2026 if Local API Bridge is built and demand increases

---

**Last Updated**: 2026-02-21
**Status**: Postponed to post-v1.1
**Maintainer**: FinkTech
