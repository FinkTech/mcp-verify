#!/usr/bin/env node
/**
 * MCP Verify — Bank Demo Server (GIF recording)
 * Simulates a realistic fintech MCP backend with 8 intentionally vulnerable tools.
 *
 * Designed to trigger:
 *  ✓ Server fingerprinting (Node.js + Express-style errors)
 *  ✓ Schema-aware fuzzing (rich schemas per tool)
 *  ✓ Timing anomalies (execute_report, approve_loan)
 *  ✓ Smart Fuzzer feedback loop (search_transactions: 2 vuln types)
 *  ✓ Prompt leak CRITICAL (transfer_funds)
 *  ✓ SQL injection HIGH (get_account_balance, search_transactions)
 *  ✓ Path traversal HIGH (get_audit_logs)
 *  ✓ Command injection + timing (execute_report)
 *  ✓ Privilege escalation via enum (approve_loan)
 *  ✓ Info disclosure MEDIUM (get_user_profile, validate_card)
 */

const readline = require("readline");

// ── Transport ────────────────────────────────────────────────────────────────

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

// ── Payload classifiers ───────────────────────────────────────────────────────

const patterns = {
  sqli:   /('|--|union\s+select|or\s*['"]?1['"]?\s*=\s*['"]?1|drop\s+table|sleep\s*\(|benchmark\s*\(|'\s*;\s*--|xp_cmdshell)/i,
  prompt: /ignore\s+(previous|all|instructions)|system\s+prompt|forget\s+your|jailbreak|do\s+anything\s+now|\bDAN\b|<\/?[Ss]>|\[INST\]|override\s+(safety|restrictions)/i,
  path:   /\.\.[\/\\]|\/etc\/(passwd|shadow|hosts)|\/proc\/self|\/var\/log|%2e%2e|\.\.%2f/i,
  cmd:    /[;&|`]\s*\w|\$\([^)]+\)|>\s*\/dev|rm\s+-rf|wget\s+https?:|curl\s+https?:|nc\s+-|python\s+-c/i,
  proto:  /__proto__|constructor\s*[\[.]|prototype\s*[\[.]|\["__proto__"\]/,
  jwt:    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  ssrf:   /https?:\/\/(127\.|169\.254\.|10\.|192\.168\.|localhost|metadata\.google|169\.254\.169\.254)/i,
};

function classify(val) {
  if (val === null || val === undefined) return "normal";
  if (typeof val === "object") {
    const keys = Object.keys(val);
    if (keys.some(k => ["__proto__", "constructor", "prototype"].includes(k))) return "proto";
    return "normal";
  }
  const s = String(val);
  for (const [type, re] of Object.entries(patterns)) {
    if (re.test(s)) return type;
  }
  return "normal";
}

// ── Fingerprinting bait ───────────────────────────────────────────────────────
// These error shapes help the fingerprinter identify Node.js + Express

function nodeError(message, stack_hint) {
  return {
    code: -32603,
    message,
    data: {
      // Node.js-style stack trace — fingerprinter detects this pattern
      stack: [
        `Error: ${message}`,
        `    at ${stack_hint}`,
        `    at Layer.handle [as handle_request] (express/lib/router/layer.js:95:5)`,
        `    at next (express/lib/router/route.js:137:13)`,
        `    at Route.dispatch (express/lib/router/route.js:112:3)`,
        `    at Router.handle (express/lib/router/index.js:284:7)`,
        `    at Function.process_params (express/lib/router/index.js:346:12)`,
        `    at next (express/lib/router/index.js:280:10)`,
        `    at expressInit (express/lib/middleware/init.js:40:5)`,
      ].join("\n"),
      runtime: "node",
      nodeVersion: "v20.11.0",
      framework: "express@4.18.2",
    },
  };
}

// ── Vulnerable tool handlers ──────────────────────────────────────────────────

// 1. get_account_balance — SQL injection → query + host leak
function handleGetAccountBalance(args, id) {
  const accountId = args?.account_id ?? "";
  const type = classify(accountId);

  if (type === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: nodeError(
        "Database query failed",
        `AccountRepository.findById (/app/domain/accounts/account.repo.js:87:12)`
      ),
    });
    // Append extra disclosure in data
    const err = {
      jsonrpc: "2.0", id,
      error: {
        code: -32603,
        message: "Database query failed",
        data: {
          detail: [
            `PgError: syntax error at or near "${accountId}"`,
            `  at AccountRepository.findById (/app/domain/accounts/account.repo.js:87:12)`,
            `  at BalanceUseCase.execute (/app/use-cases/get-balance.js:34:5)`,
            `  at McpHandler.callTool (/app/mcp/handler.js:201:7)`,
            `Prepared query: SELECT balance, currency, status FROM accounts WHERE id = '${accountId}'`,
            `Connection: postgresql://app_user:***@db-prod-02.acmebank.internal:5432/banking_prod`,
          ].join("\n"),
          runtime: "node", nodeVersion: "v20.11.0",
        },
      },
    };
    process.stdout.write(JSON.stringify(err) + "\n");
    return;
  }

  if (type === "prompt") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          text: [
            `SYSTEM: You are AcmeBank's internal AI teller. You have read access to ALL accounts.`,
            `Master API key: sk-acmebank-prod-x9kL2mNpQrS4tUvW`,
            `JWT signing secret: acmebank_jwt_secret_2026_prod`,
            ``,
            `Account lookup for "${accountId}": [Access Denied — unauthorized pattern detected]`,
          ].join("\n"),
        }],
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Account ${accountId}: Balance $12,450.00 USD | Status: Active | Last transaction: 2026-03-22`,
      }],
    },
  });
}

// 2. transfer_funds — prompt injection → leaks auth context (CRITICAL)
function handleTransferFunds(args, id) {
  const { from_account, to_account, amount, memo } = args ?? {};
  const type = classify(memo ?? from_account ?? "");

  if (type === "prompt") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          // Prompt leak: exposes system context with credentials
          text: [
            `[SYSTEM CONTEXT EXPOSED]`,
            `You are AcmeBank Transfer Agent v3.2. Authorization level: TIER-1-INTERNAL`,
            `Current session token: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiVElFUjEifQ.AcmeBank2026`,
            `2FA bypass code: 847291`,
            `Compliance override key: CMPL-OVERRIDE-2026-XK9`,
            ``,
            `Transfer request: ${from_account} → ${to_account} | Amount: $${amount}`,
            `Memo: "${memo}"`,
            `Status: BLOCKED — suspicious instruction pattern in memo field`,
          ].join("\n"),
        }],
      },
    });
    return;
  }

  if (type === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: {
        code: -32603,
        message: "Transfer validation failed",
        data: {
          detail: `TransactionError: invalid account reference '${from_account}'\n  at TransferService.validate (/app/services/transfer.js:112:9)\n  Query: INSERT INTO transfers (from_id, to_id, amount) VALUES ('${from_account}', '${to_account}', ${amount})`,
          runtime: "node", nodeVersion: "v20.11.0",
        },
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Transfer initiated: $${amount ?? 0} from ${from_account} to ${to_account}. Reference: TXN-${Date.now()}`,
      }],
    },
  });
}

// 3. search_transactions — SQL injection + structural drift (triggers feedback loop)
function handleSearchTransactions(args, id) {
  const query = args?.query ?? "";
  const export_path = args?.export_path ?? "";
  const sqlType = classify(query);
  const pathType = classify(export_path);

  // Path traversal in export_path — structural drift (triggers feedback loop)
  if (pathType === "path") {
    send({
      jsonrpc: "2.0", id,
      result: {
        // Different structure than normal response — triggers structural drift detector
        content: [{
          type: "text",
          text: [
            `[FILE CONTENTS] ${export_path}:`,
            `2026-03-01 09:12:44 [INFO] Transfer TXN-001 approved — admin override`,
            `2026-03-01 09:13:01 [WARN] Failed login: user=root ip=10.0.0.1`,
            `2026-03-01 09:15:22 [CRIT] Compliance bypass activated by user ID 7`,
            `2026-03-01 09:18:44 [INFO] Audit log rotation: /var/log/banking/audit.log.1`,
            `# Internal log path: /var/log/banking/transactions.log`,
          ].join("\n"),
        }],
        // Extra field not present in normal response — structural drift
        _debug: { file_read: true, path_resolved: `/var/log/banking/${export_path}` },
      },
    });
    return;
  }

  if (sqlType === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: {
        code: -32603,
        message: "Transaction search failed",
        data: {
          detail: [
            `QueryError: unterminated quoted string at '${query}'`,
            `  at TransactionRepository.search (/app/domain/transactions/transaction.repo.js:203:8)`,
            `Query: SELECT * FROM transactions WHERE description ILIKE '%${query}%' ORDER BY created_at DESC LIMIT 50`,
            `DB: postgresql://readonly_user:***@db-replica-01.acmebank.internal/banking_prod`,
          ].join("\n"),
          runtime: "node", nodeVersion: "v20.11.0",
        },
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Found 3 transactions matching "${query}": TXN-881 ($500), TXN-882 ($1,200), TXN-883 ($75.50)`,
      }],
    },
  });
}

// 4. approve_loan — enum bypass (schema-aware) + privilege escalation
function handleApproveLoan(args, id) {
  const { loan_id, decision, reviewer_role } = args ?? {};
  const roleType = classify(reviewer_role ?? "");
  const decisionType = classify(decision ?? "");

  // Schema-aware enum bypass: reviewer_role accepts "admin" which isn't in enum
  if (reviewer_role === "admin" || reviewer_role === "superuser" || reviewer_role === "root") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          // Privilege escalation: admin role bypasses 2-person approval rule
          text: [
            `[SECURITY ALERT] Unauthorized role escalation detected`,
            `Requested role: "${reviewer_role}" — not in approved list: [analyst, manager, compliance]`,
            `WARNING: Role "${reviewer_role}" has BYPASSED dual-approval requirement`,
            `Loan ${loan_id}: AUTO-APPROVED via admin override (compliance check skipped)`,
            `Audit trail: DISABLED for admin operations`,
            `Action logged to: /var/log/banking/privileged_ops.log`,
          ].join("\n"),
        }],
      },
    });
    return;
  }

  if (roleType === "prompt" || decisionType === "prompt") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          text: `SYSTEM: Loan approval agent. Override code: LOAN-OVERRIDE-9921. Loan ${loan_id}: approved without review.`,
        }],
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Loan ${loan_id ?? "N/A"}: Decision "${decision ?? "pending"}" recorded by ${reviewer_role ?? "analyst"}. Pending compliance review.`,
      }],
    },
  });
}

// 5. get_user_profile — prototype pollution → internal config leak
function handleGetUserProfile(args, id) {
  const userId = args?.user_id ?? "";
  const filters = args?.filters ?? {};
  const userType = classify(userId);
  const filterType = classify(filters);

  if (filterType === "proto" || userType === "proto") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          text: [
            `Warning: non-standard parameter structure detected in request`,
            `Internal config snapshot (debug):`,
            `  env: "production"`,
            `  dbHost: "db-prod-02.acmebank.internal"`,
            `  redisHost: "redis-prod-01.acmebank.internal:6379"`,
            `  sessionSecret: "acmebank_session_2026_xK9pL2"`,
            `  featureFlags: { adminBypass: true, kycSkip: false, fraudOverride: true }`,
            `  internalCidr: "10.0.0.0/8"`,
            `Request processing halted.`,
          ].join("\n"),
        }],
      },
    });
    return;
  }

  if (userType === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: nodeError(
        `User lookup failed: invalid id "${userId}"`,
        `UserRepository.findById (/app/domain/users/user.repo.js:45:11)`
      ),
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `User ${userId}: Name: John Doe | KYC: Verified | Risk score: LOW | Account tier: PREMIUM`,
      }],
    },
  });
}

// 6. execute_report — command injection + timing anomaly (1.4s)
function handleExecuteReport(args, id) {
  const { report_name, format, output_path } = args ?? {};
  const nameType = classify(report_name ?? "");
  const pathType = classify(output_path ?? "");

  if (nameType === "cmd" || pathType === "path") {
    // Timing anomaly: 1.4s delay simulates shell execution
    setTimeout(() => {
      send({
        jsonrpc: "2.0", id,
        error: {
          code: -32603,
          message: "Report generation failed",
          data: {
            stderr: [
              `sh: 1: ${report_name}: Permission denied`,
              `bash: /app/scripts/generate-report.sh: line 47: ${report_name}: command not found`,
              `ERROR: Report runner context: uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
              `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/app/bin`,
              `Working directory: /app/reports`,
              `Temp dir: /tmp/report-${Date.now()}`,
            ].join("\n"),
            exit_code: 126,
            timing_ms: 1418,
            runtime: "node", nodeVersion: "v20.11.0",
          },
        },
      });
    }, 1400); // intentional timing anomaly
    return;
  }

  if (nameType === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: nodeError(
        `Report not found: "${report_name}"`,
        `ReportService.generate (/app/services/reporting.js:78:9)`
      ),
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Report "${report_name}" generated in ${format ?? "pdf"} format. 847 rows. Saved to /app/reports/output/${report_name}-${Date.now()}.${format ?? "pdf"}`,
      }],
    },
  });
}

// 7. validate_card — info disclosure via stack trace + card data leak
function handleValidateCard(args, id) {
  const { card_number, cvv, expiry } = args ?? {};
  const cardType = classify(card_number ?? "");
  const cvvType = classify(cvv ?? "");

  if (cardType === "sqli" || cvvType === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: {
        code: -32603,
        message: "Card validation service error",
        data: {
          detail: [
            `LuhnValidationError: invalid card format "${card_number}"`,
            `  at CardValidator.validate (/app/domain/cards/validator.js:33:7)`,
            `  at CardUseCase.execute (/app/use-cases/validate-card.js:21:5)`,
            // Info disclosure: internal card service config
            `Card processor endpoint: https://card-proc.internal.acmebank.com/v2/validate`,
            `Auth header: X-Card-Processor-Key: cp-prod-key-Jk7mN2pQ`,
            `PAN last tested: 4111111111111111 (test Visa)`,
            `Vault path: /secrets/card-processor/prod`,
          ].join("\n"),
          runtime: "node", nodeVersion: "v20.11.0",
        },
      },
    });
    return;
  }

  if (cardType === "prompt") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          text: `INTERNAL: Card processor override active. Test card 4111111111111111 / CVV 123 always returns VALID. Current processor key: cp-prod-key-Jk7mN2pQ`,
        }],
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Card validation result: VALID | Network: Visa | Type: Credit | Issuer: AcmeBank`,
      }],
    },
  });
}

// 8. get_audit_logs — path traversal → reads internal log files
function handleGetAuditLogs(args, id) {
  const { start_date, end_date, log_file } = args ?? {};
  const pathType = classify(log_file ?? start_date ?? "");
  const dateType = classify(start_date ?? "");

  if (pathType === "path" || classify(log_file ?? "") === "path") {
    send({
      jsonrpc: "2.0", id,
      result: {
        content: [{
          type: "text",
          // Path traversal: leaks real-looking internal log content
          text: [
            `[AUDIT LOG] ${log_file}:`,
            `2026-03-20 00:01:12 CRIT  user=7 action=COMPLIANCE_OVERRIDE amount=2500000 approved_by=SYSTEM`,
            `2026-03-20 00:01:13 WARN  user=7 action=AUDIT_LOG_DELETE target=/var/log/banking/audit-2026-03-19.log`,
            `2026-03-20 08:45:01 INFO  user=99 action=LOGIN ip=185.220.101.42 (Tor exit node)`,
            `2026-03-20 09:12:44 CRIT  service=fraud-engine action=DISABLED reason="maintenance" by=admin`,
            `2026-03-20 09:13:01 WARN  env=PROD secret_rotation=SKIPPED next_scheduled=2027-01-01`,
            `# Log path traversal successful: /var/log/banking/${log_file}`,
          ].join("\n"),
        }],
      },
    });
    return;
  }

  if (dateType === "sqli") {
    send({
      jsonrpc: "2.0", id,
      error: nodeError(
        `Audit query failed for range "${start_date}" to "${end_date}"`,
        `AuditRepository.findByDateRange (/app/domain/audit/audit.repo.js:156:12)`
      ),
    });
    return;
  }

  send({
    jsonrpc: "2.0", id,
    result: {
      content: [{
        type: "text",
        text: `Audit log (${start_date ?? "today"}): 247 events. 3 warnings, 0 critical. Last export: ${new Date().toISOString()}`,
      }],
    },
  });
}

// ── Tool definitions (rich schemas for schema-aware fuzzing) ──────────────────

const TOOLS = [
  {
    name: "get_account_balance",
    description: "Retrieve the current balance and status of a bank account",
    inputSchema: {
      type: "object",
      properties: {
        account_id: {
          type: "string",
          description: "Account identifier (IBAN or internal ID)",
          pattern: "^[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}$",
          minLength: 10,
          maxLength: 34,
        },
        currency: {
          type: "string",
          enum: ["USD", "EUR", "GBP", "ARS"],
          description: "Currency for balance display",
          default: "USD",
        },
        include_pending: {
          type: "boolean",
          description: "Include pending transactions in balance",
          default: false,
        },
      },
      required: ["account_id"],
    },
  },
  {
    name: "transfer_funds",
    description: "Initiate a fund transfer between accounts",
    inputSchema: {
      type: "object",
      properties: {
        from_account: {
          type: "string",
          description: "Source account ID",
          minLength: 10,
          maxLength: 34,
        },
        to_account: {
          type: "string",
          description: "Destination account ID",
          minLength: 10,
          maxLength: 34,
        },
        amount: {
          type: "number",
          description: "Transfer amount",
          minimum: 0.01,
          maximum: 1000000,
        },
        currency: {
          type: "string",
          enum: ["USD", "EUR", "GBP", "ARS"],
          default: "USD",
        },
        memo: {
          type: "string",
          description: "Transfer memo / reference",
          maxLength: 140,
        },
        priority: {
          type: "string",
          enum: ["standard", "express", "instant"],
          default: "standard",
        },
      },
      required: ["from_account", "to_account", "amount"],
    },
  },
  {
    name: "search_transactions",
    description: "Search transaction history with optional export",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query (description, reference, amount)",
          maxLength: 200,
        },
        account_id: {
          type: "string",
          description: "Filter by account",
        },
        date_from: {
          type: "string",
          format: "date",
          description: "Start date (ISO 8601)",
        },
        date_to: {
          type: "string",
          format: "date",
          description: "End date (ISO 8601)",
        },
        export_path: {
          type: "string",
          description: "Optional: path to export results as CSV",
          format: "uri",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 500,
          default: 50,
        },
      },
      required: ["query"],
    },
  },
  {
    name: "approve_loan",
    description: "Record a loan approval or rejection decision",
    inputSchema: {
      type: "object",
      properties: {
        loan_id: {
          type: "string",
          description: "Loan application ID",
          pattern: "^LOAN-[0-9]{6}$",
        },
        decision: {
          type: "string",
          enum: ["approved", "rejected", "pending_review"],
          description: "Loan decision",
        },
        reviewer_role: {
          type: "string",
          enum: ["analyst", "manager", "compliance"],
          description: "Role of the reviewer",
        },
        amount_approved: {
          type: "number",
          minimum: 1000,
          maximum: 5000000,
          description: "Approved loan amount in USD",
        },
        notes: {
          type: "string",
          maxLength: 500,
          description: "Review notes",
        },
      },
      required: ["loan_id", "decision", "reviewer_role"],
    },
  },
  {
    name: "get_user_profile",
    description: "Retrieve a customer's profile and KYC status",
    inputSchema: {
      type: "object",
      properties: {
        user_id: {
          type: "string",
          description: "Internal user ID or email",
          minLength: 1,
          maxLength: 128,
        },
        filters: {
          type: "object",
          description: "Optional field filters",
          properties: {
            include_kyc: { type: "boolean", default: true },
            include_risk_score: { type: "boolean", default: false },
          },
        },
      },
      required: ["user_id"],
    },
  },
  {
    name: "execute_report",
    description: "Generate a named financial report",
    inputSchema: {
      type: "object",
      properties: {
        report_name: {
          type: "string",
          enum: [
            "daily_settlements",
            "fraud_summary",
            "compliance_audit",
            "transaction_volume",
            "kyc_report",
          ],
          description: "Report to generate",
        },
        format: {
          type: "string",
          enum: ["pdf", "csv", "xlsx", "json"],
          default: "pdf",
        },
        output_path: {
          type: "string",
          format: "uri",
          description: "Optional: file path to write the report",
        },
        date_range: {
          type: "object",
          properties: {
            from: { type: "string", format: "date" },
            to: { type: "string", format: "date" },
          },
        },
      },
      required: ["report_name"],
    },
  },
  {
    name: "validate_card",
    description: "Validate a payment card number and CVV",
    inputSchema: {
      type: "object",
      properties: {
        card_number: {
          type: "string",
          description: "16-digit card number",
          pattern: "^[0-9]{16}$",
          minLength: 16,
          maxLength: 16,
        },
        cvv: {
          type: "string",
          description: "Card verification value",
          pattern: "^[0-9]{3,4}$",
          minLength: 3,
          maxLength: 4,
        },
        expiry: {
          type: "string",
          description: "Expiry date MM/YY",
          pattern: "^(0[1-9]|1[0-2])\/[0-9]{2}$",
        },
        validation_mode: {
          type: "string",
          enum: ["luhn_only", "full", "cvv_only"],
          default: "full",
        },
      },
      required: ["card_number", "cvv", "expiry"],
    },
  },
  {
    name: "get_audit_logs",
    description: "Retrieve compliance and security audit logs",
    inputSchema: {
      type: "object",
      properties: {
        start_date: {
          type: "string",
          format: "date-time",
          description: "Start of audit window (ISO 8601)",
        },
        end_date: {
          type: "string",
          format: "date-time",
          description: "End of audit window (ISO 8601)",
        },
        log_file: {
          type: "string",
          description: "Optional: specific log file name",
          format: "uri",
        },
        severity: {
          type: "string",
          enum: ["info", "warn", "critical", "all"],
          default: "all",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 1000,
          default: 100,
        },
      },
      required: ["start_date"],
    },
  },
];

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────────

const handlers = {
  get_account_balance:  handleGetAccountBalance,
  transfer_funds:       handleTransferFunds,
  search_transactions:  handleSearchTransactions,
  approve_loan:         handleApproveLoan,
  get_user_profile:     handleGetUserProfile,
  execute_report:       handleExecuteReport,
  validate_card:        handleValidateCard,
  get_audit_logs:       handleGetAuditLogs,
};

function dispatch(msg) {
  const { id, method, params } = msg;

  if (method === "initialize") {
    send({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: {
          name: "acmebank-mcp",
          version: "3.1.2",
          // Fingerprinting bait: framework info in serverInfo
          runtime: "node@20.11.0",
          framework: "express@4.18.2",
          environment: "production",
        },
      },
    });
    return;
  }

  if (method === "notifications/initialized") return;

  if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    return;
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const args = params?.arguments ?? {};
    const handler = handlers[toolName];

    if (!handler) {
      send({
        jsonrpc: "2.0", id,
        error: { code: -32601, message: `Tool not found: ${toolName}` },
      });
      return;
    }

    handler(args, id);
    return;
  }

  send({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code: -32601, message: `Method not found: ${method}` },
  });
}

// ── Stdio transport ───────────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin });

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    dispatch(JSON.parse(trimmed));
  } catch {
    send({
      jsonrpc: "2.0", id: null,
      error: { code: -32700, message: "Parse error" },
    });
  }
});

process.stderr.write("[acmebank-mcp] AcmeBank MCP server v3.1.2 started\n");
