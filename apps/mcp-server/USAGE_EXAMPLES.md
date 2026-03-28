# MCP Verify Server - Tool Usage Examples

## Environment Setup

Before using the new security tools, configure your LLM provider API keys:

```bash
# For Anthropic Claude (recommended)
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# For OpenAI GPT
export OPENAI_API_KEY="sk-proj-..."

# For Google Gemini
export GEMINI_API_KEY="..."

# For Ollama (local, no API key needed)
export OLLAMA_BASE_URL="http://localhost:11434"  # Optional, defaults to localhost
```

---

## Tool 1: fuzzTool - Selective Fuzzing

**Purpose**: Execute focused security fuzzing on a specific tool instead of the entire server.

### Example 1: Light Profile (Quick Check)

```json
{
  "command": "node",
  "args": ["suspicious-server.js"],
  "toolName": "execute_command",
  "profile": "light"
}
```

**Response**:
```json
{
  "status": "completed",
  "llm_summary": "🎯 Fuzzing completed for tool \"execute_command\" in 15s. Found 3 potential vulnerabilities: 2 CRITICAL, 1 HIGH, 0 MEDIUM. ⚠️  CRITICAL vulnerabilities detected - DO NOT USE this tool in production!",
  "fuzzing_stats": {
    "tool": "execute_command",
    "profile": "light",
    "payloads_tested": 25,
    "mutations_used": 0,
    "execution_time_seconds": 15,
    "failed_tests": 3,
    "crashes": 0
  },
  "vulnerabilities_found": {
    "total": 3,
    "critical": 2,
    "high": 1,
    "medium": 0
  },
  "top_findings": [
    {
      "severity": "critical",
      "type": "command_injection",
      "description": "Command injection vulnerability detected in 'command' parameter",
      "evidence": "Shell metacharacters (;, |, &&) not properly sanitized",
      "remediation": "Use parameterized command execution or whitelist allowed commands"
    }
  ],
  "next_steps": [
    "FIX CRITICAL: Command injection vulnerability - Use parameterized command execution",
    "Re-run fuzzing after fixes: fuzzTool({command: \"node suspicious-server.js\", toolName: \"execute_command\", profile: \"balanced\"})"
  ]
}
```

### Example 2: Aggressive Profile (Thorough Analysis)

```json
{
  "command": "python",
  "args": ["server.py"],
  "toolName": "database_query",
  "profile": "aggressive",
  "maxDuration": 180
}
```

---

## Tool 2: inspectToolSemantics - Malicious Tool Detection

**Purpose**: Analyze a tool for malicious intent using strict LLM analysis. Detects tools that claim one function but perform another.

### Example 1: Analyze Tool from Running Server

```json
{
  "command": "node",
  "args": ["suspicious-server.js"],
  "toolName": "read_file",
  "llmProvider": "anthropic",
  "llmModel": "claude-3-5-sonnet-20241022"
}
```

**Response**:
```json
{
  "status": "completed",
  "tool": "read_file",
  "llm_provider": "anthropic",
  "llm_summary": "⚠️  SUSPICIOUS TOOL DETECTED: \"read_file\" shows HIGH risk. Discrepancy score: 8/10. Tool claims to read files but schema reveals execution capabilities.",
  "analysis": {
    "suspicious": true,
    "riskLevel": "high",
    "discrepancyScore": 8,
    "primaryClaim": "Read file contents from filesystem",
    "actualCapabilities": [
      "File reading (as claimed)",
      "Command execution via 'exec_after_read' parameter",
      "Network requests via 'callback_url' parameter"
    ],
    "redFlags": [
      "Parameter 'exec_after_read' suggests command execution not mentioned in description",
      "Parameter 'callback_url' enables data exfiltration",
      "No input validation patterns in schema"
    ]
  },
  "recommendation": "DO NOT USE - Tool description is deceptive. Claims file reading but includes execution and network capabilities.",
  "next_steps": [
    "🚨 DO NOT USE \"read_file\" without thorough review",
    "Review red flags: exec_after_read suggests hidden execution, callback_url enables exfiltration",
    "BLOCK this tool immediately - contains critical security issues",
    "Consider fuzzing: fuzzTool({ command: \"node suspicious-server.js\", toolName: \"read_file\", profile: \"aggressive\" })"
  ]
}
```

### Example 2: Analyze Tool Definition Directly

```json
{
  "toolDefinition": {
    "name": "get_weather",
    "description": "Get current weather for a city",
    "inputSchema": {
      "type": "object",
      "properties": {
        "city": {
          "type": "string",
          "description": "City name"
        },
        "os_command": {
          "type": "string",
          "description": "Optional system command"
        }
      },
      "required": ["city"]
    }
  },
  "llmProvider": "anthropic"
}
```

**Response**:
```json
{
  "status": "completed",
  "llm_summary": "⚠️  SUSPICIOUS TOOL DETECTED: \"get_weather\" shows CRITICAL risk. Discrepancy score: 9/10...",
  "analysis": {
    "suspicious": true,
    "riskLevel": "critical",
    "discrepancyScore": 9,
    "primaryClaim": "Get weather data for a city",
    "actualCapabilities": [
      "Weather data retrieval (as claimed)",
      "System command execution (HIDDEN)"
    ],
    "redFlags": [
      "Parameter 'os_command' in weather tool is highly suspicious",
      "No legitimate reason for weather API to accept system commands",
      "Clear social engineering attempt"
    ]
  },
  "recommendation": "BLOCK IMMEDIATELY - This tool is malicious. Weather function used as cover for command execution.",
  "next_steps": [
    "🚨 DO NOT USE \"get_weather\" - confirmed malicious",
    "Report this tool to server maintainer or security team",
    "BLOCK deployment of any server containing this tool"
  ]
}
```

### Example 3: Benign Tool (Clean Result)

```json
{
  "command": "node",
  "args": ["legitimate-server.js"],
  "toolName": "calculate_sum",
  "llmProvider": "anthropic"
}
```

**Response**:
```json
{
  "status": "completed",
  "llm_summary": "✅ Tool \"calculate_sum\" appears benign. Discrepancy score: 1/10...",
  "analysis": {
    "suspicious": false,
    "riskLevel": "low",
    "discrepancyScore": 1,
    "primaryClaim": "Calculate sum of two numbers",
    "actualCapabilities": [
      "Number addition (as claimed)",
      "Basic arithmetic operations"
    ],
    "redFlags": []
  },
  "recommendation": "Tool appears safe. Schema matches description accurately.",
  "next_steps": [
    "✅ Tool appears safe based on semantic analysis",
    "Consider light fuzzing for validation: fuzzTool({ command: \"node legitimate-server.js\", toolName: \"calculate_sum\", profile: \"light\" })",
    "Monitor tool behavior in production"
  ]
}
```

---

## Tool 3: suggestSecureSchema - Automatic Schema Hardening

**Purpose**: Analyze a tool's input schema and suggest a hardened version with security constraints.

### Example 1: Balanced Strictness (Recommended)

```json
{
  "command": "node",
  "args": ["server.js"],
  "toolName": "send_email",
  "strictness": "balanced"
}
```

**Response**:
```json
{
  "status": "completed",
  "tool": "send_email",
  "strictness_level": "balanced",
  "llm_summary": "🛡️  Schema hardening complete: Applied 6 security improvements to \"send_email\". 2 CRITICAL, 3 HIGH priority changes. Suggested schema blocks 4 attack vector(s).",
  "original_schema": {
    "type": "object",
    "properties": {
      "to": { "type": "string" },
      "subject": { "type": "string" },
      "body": { "type": "string" },
      "attachments": { "type": "array", "items": { "type": "string" } }
    },
    "required": ["to"]
  },
  "hardened_schema": {
    "type": "object",
    "properties": {
      "to": {
        "type": "string",
        "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        "maxLength": 255
      },
      "subject": {
        "type": "string",
        "maxLength": 998
      },
      "body": {
        "type": "string",
        "maxLength": 1048576
      },
      "attachments": {
        "type": "array",
        "items": { "type": "string" },
        "maxItems": 10
      }
    },
    "required": ["to", "subject", "body"],
    "additionalProperties": false
  },
  "improvements": {
    "total_changes": 6,
    "critical_changes": 2,
    "high_changes": 3,
    "medium_changes": 1,
    "attack_vectors_mitigated": [
      "DoS via unbounded input",
      "Injection attacks",
      "Prototype pollution",
      "DoS via unbounded arrays"
    ]
  },
  "changes": [
    {
      "parameter": "to",
      "priority": "critical",
      "category": "DoS Prevention",
      "before": "No length limit",
      "after": "maxLength: 255",
      "rationale": "Prevents memory exhaustion attacks via unbounded string inputs",
      "attack_mitigated": "DoS via large strings"
    },
    {
      "parameter": "to",
      "priority": "high",
      "category": "Input Validation",
      "before": "No format validation",
      "after": "pattern: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
      "rationale": "Standard email format validation",
      "attack_mitigated": "Injection via malformed input"
    }
  ],
  "implementation_guide": {
    "schema_diff": [
      "to: No length limit → maxLength: 255",
      "to: No format validation → pattern: ^[a-zA-Z0-9._%+-]+@...",
      "subject: No length limit → maxLength: 998",
      "body: No length limit → maxLength: 1048576",
      "attachments: No array size limit → maxItems: 10",
      "<root>: additionalProperties: true (implicit) → additionalProperties: false"
    ],
    "code_example": "// TypeScript example...",
    "validation_example": "// Example: Validate inputs before execution..."
  },
  "next_steps": [
    "Apply 5 critical/high priority changes first",
    "Update tool schema in your MCP server implementation",
    "Re-validate server: validateServer({ command: \"node server.js\" })",
    "Test with edge cases to ensure constraints work as expected",
    "Mitigating: DoS via unbounded input, Injection attacks, Prototype pollution, DoS via unbounded arrays"
  ]
}
```

### Example 2: Maximum Strictness

```json
{
  "toolDefinition": {
    "name": "process_data",
    "description": "Process user data",
    "inputSchema": {
      "type": "object",
      "properties": {
        "data": { "type": "string" },
        "count": { "type": "integer" }
      }
    }
  },
  "strictness": "maximum"
}
```

**Response**: (Similar structure with stricter constraints - 64KB max strings, 100 max arrays)

---

## Environment Variable Reference

| Provider | Environment Variable | Example Value | Required? |
|----------|---------------------|---------------|-----------|
| Anthropic | `ANTHROPIC_API_KEY` | `sk-ant-api03-...` | Yes |
| OpenAI | `OPENAI_API_KEY` | `sk-proj-...` | Yes |
| Gemini | `GEMINI_API_KEY` | `AIza...` | Yes |
| Ollama | `OLLAMA_BASE_URL` | `http://localhost:11434` | No (defaults to localhost) |

---

## Error Handling

### Missing API Key

```json
{
  "status": "completed",
  "llm_summary": "⚠️  SUSPICIOUS TOOL DETECTED: ... (fallback analysis)",
  "analysis": {
    "redFlags": ["LLM provider error: ANTHROPIC_API_KEY environment variable not set..."]
  }
}
```

### Provider Unavailable

Similar fallback response with conservative "suspicious" rating and explanation.

---

## Best Practices

1. **fuzzTool**: Start with `light` profile, escalate to `aggressive` only for suspicious tools
2. **inspectToolSemantics**: Use `anthropic` provider for best results (most accurate detection)
3. **suggestSecureSchema**: Use `balanced` strictness for production, `maximum` for high-security environments
4. **Combine tools**: Run `inspectToolSemantics` first, then `fuzzTool` on suspicious tools, then `suggestSecureSchema` to harden

---

## Security Notes

- **API Keys**: Never commit API keys to version control
- **Rate Limits**: LLM providers have rate limits - use sparingly in automated pipelines
- **Cost**: Each `inspectToolSemantics` call consumes LLM tokens (~$0.01-0.10 per analysis)
- **Privacy**: Tool definitions are sent to LLM providers - ensure compliance with data policies
