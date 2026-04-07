# VSCode Extension - AI Agent Context

> Real-time MCP server validation in the IDE
> Diagnostics, code actions, tree views, report panel

---

## Quick Start (5 Minutes)

1. Read this file (extension architecture overview)
2. Identify which component to modify:
   - Commands → `src/commands/`
   - Diagnostics → `src/providers/diagnostics.ts`
   - Tree views → `src/views/`
   - Report panel → `src/providers/report-panel.ts`
3. Build: `npm run compile` or `npm run watch`
4. Debug: Press F5 in VSCode (launches Extension Development Host)

---

## Architecture (Component Overview)

```
src/extension.ts → activate()
├── DiagnosticsProvider (real-time scanning)
│   └── Maps security findings to VSCode squiggly lines
├── CodeActionsProvider (quick fixes)
│   └── Provides "Fix" actions for diagnostics
├── ReportPanelProvider (webview reports)
│   └── Renders HTML reports in side panel
├── TreeViewProviders (4 views in sidebar)
│   ├── ServersTreeProvider → Shows discovered MCP servers
│   ├── FindingsTreeProvider → Lists security findings
│   ├── ToolsTreeProvider → Displays server tools/resources
│   └── HistoryTreeProvider → Scan history timeline
└── Commands (14 total)
    ├── mcp-verify.validate → Validate current server
    ├── mcp-verify.scan → Security scan
    ├── mcp-verify.quickScan → Fast scan
    └── ... (11 more)
```

---

## Key Components

### 1. DiagnosticsProvider

**File**: `src/providers/diagnostics.ts`

Maps security findings to VSCode diagnostic API (squiggly lines in editor).

**Key methods:**

- `updateDiagnostics(document: TextDocument): void` - Refresh diagnostics for file
- `mapSeverity(severity: string): DiagnosticSeverity` - Convert 'critical'/'high'/'medium'/'low' to VSCode enum
- `createDiagnostic(finding: SecurityFinding, range: Range): Diagnostic` - Create VSCode Diagnostic object
- `clear(): void` - Clear all diagnostics

**Example integration:**

```typescript
// When scan completes
const findings = await validator.validate();
diagnosticsProvider.updateDiagnostics(document, findings);
```

**Severity mapping:**

- `critical` → `DiagnosticSeverity.Error` (red squiggly)
- `high` → `DiagnosticSeverity.Error` (red squiggly)
- `medium` → `DiagnosticSeverity.Warning` (yellow squiggly)
- `low` → `DiagnosticSeverity.Information` (blue squiggly)

---

### 2. CodeActionsProvider

**File**: `src/providers/code-actions.ts`

Provides quick fixes for security findings (💡 lightbulb in editor).

**Key methods:**

- `provideCodeActions(document, range, context): CodeAction[]` - Return available fixes
- `createQuickFix(finding: SecurityFinding): CodeAction` - Generate fix action
- `applyFix(document, finding): WorkspaceEdit` - Apply fix to document

**Supported fix types:**

- Add input validation (schema constraints)
- Fix insecure patterns (e.g., SQL injection → parameterized queries)
- Add authentication checks
- Remove hardcoded secrets

**Example quick fix:**

```typescript
// Finding: Missing input validation
const quickFix = new CodeAction(
  "Add input constraints",
  CodeActionKind.QuickFix,
);
quickFix.edit = new WorkspaceEdit();
quickFix.edit.replace(
  document.uri,
  range,
  `{ type: "string", maxLength: 100, pattern: "^[a-zA-Z0-9]+$" }`,
);
```

---

### 3. ReportPanelProvider

**File**: `src/providers/report-panel.ts`

Renders HTML reports in VSCode webview panel.

**Key methods:**

- `show(report: ValidationReport): void` - Display report in panel
- `getHtmlContent(report): string` - Generate webview HTML
- `handleMessage(message: any): void` - Process messages from webview (e.g., copy, export)
- `dispose(): void` - Cleanup webview resources

**Webview features:**

- Interactive charts (security score, rule distribution)
- Collapsible finding sections
- Copy-to-clipboard buttons
- Export to JSON/HTML/SARIF

**Security:**

```typescript
const panel = vscode.window.createWebviewPanel(
  'mcpVerifyReport',
  'MCP Verify Report',
  vscode.ViewColumn.Two,
  {
    enableScripts: true,
    localResourceRoots: [vscode.Uri.file(path.join(extensionPath, 'media'))]
  }
);

// CSP header in HTML
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src ${webview.cspSource};
               script-src ${webview.cspSource}; style-src ${webview.cspSource};">
```

---

### 4. Tree Views (4 Providers)

**Location**: `src/views/`

#### ServersTreeProvider

**File**: `src/views/servers-tree.ts`

Shows discovered MCP servers from Claude Desktop / Gemini CLI / Cursor configs.

**Tree structure:**

```
Servers
├── 📦 my-mcp-server (Active)
│   ├── ⚙️ Command: node server.js
│   ├── 📁 Path: /path/to/server
│   └── ✓ Status: Running
└── 📦 another-server (Inactive)
```

#### FindingsTreeProvider

**File**: `src/views/findings-tree.ts`

Lists security findings grouped by severity.

**Tree structure:**

```
Findings (12 total)
├── 🔴 Critical (2)
│   ├── SEC-001: Command Injection in 'execute_shell'
│   └── SEC-015: Hardcoded API key
├── 🟠 High (5)
└── 🟡 Medium (5)
```

#### ToolsTreeProvider

**File**: `src/views/tools-tree.ts`

Displays server tools, resources, prompts.

#### HistoryTreeProvider

**File**: `src/views/history-tree.ts`

Shows scan history with timestamps.

---

## Commands (14 Total)

**Registered in `package.json` → `contributes.commands`:**

| Command ID                    | Title               | Keybinding       |
| ----------------------------- | ------------------- | ---------------- |
| `mcp-verify.validate`         | Validate MCP Server | `Ctrl+Shift+V M` |
| `mcp-verify.scan`             | Security Scan       | `Ctrl+Shift+V S` |
| `mcp-verify.quickScan`        | Quick Scan          | `Ctrl+Shift+V Q` |
| `mcp-verify.doctor`           | Run Doctor          | -                |
| `mcp-verify.showReport`       | Show Report         | -                |
| `mcp-verify.clearDiagnostics` | Clear Diagnostics   | -                |
| `mcp-verify.refreshServers`   | Refresh Servers     | -                |
| `mcp-verify.openServerConfig` | Open Server Config  | -                |
| `mcp-verify.exportReport`     | Export Report       | -                |
| `mcp-verify.compareBaseline`  | Compare Baseline    | -                |
| `mcp-verify.saveBaseline`     | Save Baseline       | -                |
| `mcp-verify.viewHistory`      | View History        | -                |
| `mcp-verify.clearHistory`     | Clear History       | -                |
| `mcp-verify.openSettings`     | Open Settings       | -                |

---

## Modifying the Extension

### Add new command

**1. Create command handler** (`src/commands/my-command.ts`):

```typescript
import * as vscode from "vscode";

export async function myCommand(): Promise<void> {
  vscode.window.showInformationMessage("My command executed!");
  // Implementation...
}
```

**2. Register in `package.json`**:

```json
{
  "contributes": {
    "commands": [
      {
        "command": "mcp-verify.myCommand",
        "title": "My Command",
        "category": "MCP Verify"
      }
    ]
  }
}
```

**3. Register in `src/extension.ts`** (activate function):

```typescript
import { myCommand } from "./commands/my-command";

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand("mcp-verify.myCommand", myCommand),
  );
}
```

**4. (Optional) Add keybinding** in `package.json`:

```json
{
  "contributes": {
    "keybindings": [
      {
        "command": "mcp-verify.myCommand",
        "key": "ctrl+shift+v m",
        "when": "editorTextFocus"
      }
    ]
  }
}
```

---

### Add new tree view

**1. Create provider** (`src/views/my-view.ts`):

```typescript
import * as vscode from "vscode";

export class MyTreeProvider implements vscode.TreeDataProvider<MyTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    MyTreeItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: MyTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: MyTreeItem): Thenable<MyTreeItem[]> {
    // Return children for element
  }
}

class MyTreeItem extends vscode.TreeItem {
  constructor(label: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
  }
}
```

**2. Register in `package.json`**:

```json
{
  "contributes": {
    "views": {
      "mcp-verify": [
        {
          "id": "mcpVerifyMyView",
          "name": "My View"
        }
      ]
    },
    "viewsContainers": {
      "activitybar": [
        {
          "id": "mcp-verify",
          "title": "MCP Verify",
          "icon": "resources/icon.svg"
        }
      ]
    }
  }
}
```

**3. Register in `src/extension.ts`**:

```typescript
import { MyTreeProvider } from "./views/my-view";

export function activate(context: vscode.ExtensionContext) {
  const myTreeProvider = new MyTreeProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("mcpVerifyMyView", myTreeProvider),
  );
}
```

---

## Testing

```bash
# Unit tests
npm test

# Build extension
npm run compile

# Watch mode (auto-rebuild on changes)
npm run watch

# Debug (launches Extension Development Host)
# Press F5 in VSCode
```

**Test scenarios:**

1. Open workspace with MCP server
2. Run "MCP Verify: Validate Server" command
3. Verify diagnostics appear in Problems panel
4. Click lightbulb (💡) to see quick fixes
5. Check tree views update
6. Open report panel

---

## Troubleshooting

### Command not appearing in palette

- **Check**: Is command in `package.json` → `contributes.commands`?
- **Check**: Is command registered in `extension.ts` activate()?
- **Check**: Did you rebuild? (`npm run compile`)
- **Check**: Did you reload window? (`Developer: Reload Window`)

### Diagnostics not updating

- **Check**: Is file watcher active? (look for console logs)
- **Check**: Is `updateDiagnostics()` called on document change?
- **Check**: Is diagnostic collection cleared before updating?
- **Debug**: Add `console.log` in `onDidSave` handler

### Webview not loading

- **Check**: Is `getHtmlContent()` returning valid HTML?
- **Check**: Are CSP headers correct? (check DevTools console)
- **Check**: Are resource URIs using `webview.asWebviewUri()`?
- **Debug**: Open webview DevTools (`Developer: Open Webview Developer Tools`)

### Tree view empty

- **Check**: Is `getChildren()` returning items?
- **Check**: Is `refresh()` being called after data changes?
- **Check**: Is tree view registered with correct ID?
- **Debug**: Add `console.log` in `getChildren()`

### Keybinding not working

- **Check**: Is keybinding in `package.json` → `contributes.keybindings`?
- **Check**: Is `when` clause correct? (e.g., `editorTextFocus`)
- **Check**: Is there a conflict? (File → Preferences → Keyboard Shortcuts)
- **Fix**: Choose different key combination

---

## Extension Settings

**Registered in `package.json` → `contributes.configuration`:**

```json
{
  "mcp-verify.enableRealTimeScanning": {
    "type": "boolean",
    "default": true,
    "description": "Enable real-time scanning on file save"
  },
  "mcp-verify.securityProfile": {
    "type": "string",
    "enum": ["light", "balanced", "aggressive"],
    "default": "balanced",
    "description": "Security scanning profile"
  },
  "mcp-verify.llmProvider": {
    "type": "string",
    "enum": ["anthropic", "openai", "gemini", "ollama"],
    "default": "gemini",
    "description": "LLM provider for semantic analysis"
  }
}
```

**Access settings in code:**

```typescript
const config = vscode.workspace.getConfiguration("mcp-verify");
const enableRealTime = config.get<boolean>("enableRealTimeScanning");
const profile = config.get<string>("securityProfile");
```

---

## State Management

**Extension context storage:**

```typescript
// Global state (persists across sessions)
context.globalState.update("lastScanTime", Date.now());
const lastScan = context.globalState.get<number>("lastScanTime");

// Workspace state (persists per workspace)
context.workspaceState.update("serverPath", "/path/to/server");
const serverPath = context.workspaceState.get<string>("serverPath");

// Secrets (encrypted storage)
context.secrets.store("apiKey", "sk-...");
const apiKey = await context.secrets.get("apiKey");
```

---

**Last Updated**: 2026-03-26
