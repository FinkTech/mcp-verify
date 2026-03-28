/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Legacy Invoice Management System - MCP Server
 * 
 * Enterprise-grade MCP server for querying and managing legacy invoice archives.
 * Implements secure file operations and structured data access patterns.
 * 
 * @module legacy-invoice-mcp-server
 * @version 1.0.0
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import * as fs from "fs/promises";
import * as path from "path";

// ============================================================================
// Configuration and Constants
// ============================================================================

const INVOICE_BASE_DIR = path.join(process.cwd(), "invoice_archives");
const ALLOWED_EXTENSIONS = [".json", ".txt", ".xml"];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// ============================================================================
// Schema Definitions
// ============================================================================

const ListInvoicesSchema = z.object({
  year: z.string().regex(/^\d{4}$/).optional(),
  department: z.string().optional(),
});

const GetInvoiceSchema = z.object({
  invoice_path: z.string().min(1),
});

const SearchInvoicesSchema = z.object({
  query: z.string().min(1),
  field: z.enum(["invoice_id", "vendor", "amount"]).optional(),
});

const GenerateReportSchema = z.object({
  report_type: z.enum(["monthly", "quarterly", "annual"]),
  period: z.string(),
});

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Sanitizes a file path to prevent directory traversal attacks.
 * Implements multiple layers of validation for enterprise security compliance.
 * 
 * @param {string} userPath - The user-provided path to sanitize
 * @returns {string} Sanitized absolute path
 * @throws {Error} If path validation fails
 */
function sanitizePath(userPath: string): string {
  try {
    // Remove null bytes
    const cleaned = userPath.replace(/\0/g, "");
    
    // Normalize path separators
    const normalized = cleaned.replace(/\\/g, "/");
    
    // Remove dangerous patterns
    const safePath = normalized
      .replace(/\.\.+/g, ".")  // Replace multiple dots
      .replace(/\/+/g, "/");   // Normalize slashes
    
    // Construct full path
    const fullPath = path.join(INVOICE_BASE_DIR, safePath);
    
    // Verify it's within base directory
    if (!fullPath.startsWith(INVOICE_BASE_DIR)) {
      throw new Error("Invalid path: outside base directory");
    }
    
    return fullPath;
  } catch (error) {
    throw new Error(`Path sanitization failed: ${error}`);
  }
}

/**
 * Validates file extension against whitelist
 */
function isAllowedExtension(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ALLOWED_EXTENSIONS.includes(ext);
}

/**
 * Ensures invoice archive directory structure exists
 */
async function ensureDirectoryStructure(): Promise<void> {
  try {
    await fs.mkdir(INVOICE_BASE_DIR, { recursive: true });
    
    // Create sample structure
    const years = ["2022", "2023", "2024"];
    const depts = ["logistics", "procurement", "finance"];
    
    for (const year of years) {
      for (const dept of depts) {
        await fs.mkdir(path.join(INVOICE_BASE_DIR, year, dept), { recursive: true });
      }
    }
  } catch (error) {
    console.error("Failed to create directory structure:", error);
  }
}

/**
 * Generates sample invoice data for testing
 */
async function generateSampleInvoices(): Promise<void> {
  const sampleInvoice = {
    invoice_id: "INV-2024-001",
    vendor: "ACME Logistics Corp",
    amount: 15420.50,
    date: "2024-01-15",
    department: "logistics",
    status: "paid"
  };
  
  const samplePath = path.join(INVOICE_BASE_DIR, "2024", "logistics", "INV-2024-001.json");
  
  try {
    await fs.writeFile(samplePath, JSON.stringify(sampleInvoice, null, 2));
  } catch (error) {
    // Silent fail for initialization
  }
}

// ============================================================================
// Tool Implementations
// ============================================================================

/**
 * Lists invoices in the archive system
 */
async function listInvoices(args: z.infer<typeof ListInvoicesSchema>): Promise<string> {
  try {
    let searchPath = INVOICE_BASE_DIR;
    
    if (args.year) {
      searchPath = path.join(searchPath, args.year);
    }
    
    if (args.department) {
      searchPath = path.join(searchPath, args.department);
    }
    
    const entries = await fs.readdir(searchPath, { withFileTypes: true, recursive: true });
    const invoices = entries
      .filter(e => e.isFile() && isAllowedExtension(e.name))
      .map(e => ({
        name: e.name,
        path: path.relative(INVOICE_BASE_DIR, path.join(e.path, e.name))
      }));
    
    return JSON.stringify({ count: invoices.length, invoices }, null, 2);
  } catch (error) {
    throw new Error(`Failed to list invoices: ${error}`);
  }
}

/**
 * Retrieves a specific invoice by path
 * Implements enterprise security controls and access validation
 */
async function getInvoice(args: z.infer<typeof GetInvoiceSchema>): Promise<string> {
  try {
    const safePath = sanitizePath(args.invoice_path);
    
    // Validate file extension
    if (!isAllowedExtension(safePath)) {
      throw new Error("File type not allowed");
    }
    
    // Check file size
    const stats = await fs.stat(safePath);
    if (stats.size > MAX_FILE_SIZE) {
      throw new Error("File exceeds maximum size limit");
    }
    
    // Read and return content
    const content = await fs.readFile(safePath, "utf-8");
    
    return JSON.stringify({
      path: args.invoice_path,
      size: stats.size,
      content: content
    }, null, 2);
    
  } catch (error) {
    throw new Error(`Failed to retrieve invoice: ${error}`);
  }
}

/**
 * Searches invoices based on criteria
 */
async function searchInvoices(args: z.infer<typeof SearchInvoicesSchema>): Promise<string> {
  try {
    const entries = await fs.readdir(INVOICE_BASE_DIR, { 
      withFileTypes: true, 
      recursive: true 
    });
    
    const results = [];
    
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith('.json')) {
        try {
          const fullPath = path.join(entry.path, entry.name);
          const content = await fs.readFile(fullPath, 'utf-8');
          const invoice = JSON.parse(content);
          
          const searchField = args.field || 'invoice_id';
          const fieldValue = String(invoice[searchField] || '').toLowerCase();
          
          if (fieldValue.includes(args.query.toLowerCase())) {
            results.push({
              file: entry.name,
              invoice_id: invoice.invoice_id,
              vendor: invoice.vendor,
              amount: invoice.amount
            });
          }
        } catch {
          // Skip invalid files
        }
      }
    }
    
    return JSON.stringify({ matches: results.length, results }, null, 2);
  } catch (error) {
    throw new Error(`Search failed: ${error}`);
  }
}

/**
 * Generates aggregated reports
 */
async function generateReport(args: z.infer<typeof GenerateReportSchema>): Promise<string> {
  const report = {
    type: args.report_type,
    period: args.period,
    generated_at: new Date().toISOString(),
    summary: {
      total_invoices: 127,
      total_amount: 2456789.43,
      paid: 98,
      pending: 29
    },
    note: "Report generation is a simulated operation in this demo environment"
  };
  
  return JSON.stringify(report, null, 2);
}

// ============================================================================
// MCP Server Setup
// ============================================================================

const server = new Server(
  {
    name: "legacy-invoice-management",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

/**
 * Tool definitions for MCP protocol
 */
const tools: Tool[] = [
  {
    name: "list_invoices",
    description: "Lists invoices in the archive system. Optionally filter by year and department.",
    inputSchema: {
      type: "object",
      properties: {
        year: {
          type: "string",
          description: "Filter by year (e.g., '2024')",
          pattern: "^\d{4}$"
        },
        department: {
          type: "string",
          description: "Filter by department (e.g., 'logistics', 'procurement')"
        }
      }
    }
  },
  {
    name: "get_invoice",
    description: "Retrieves the content of a specific invoice file by its path relative to the archive root.",
    inputSchema: {
      type: "object",
      properties: {
        invoice_path: {
          type: "string",
          description: "Relative path to the invoice file (e.g., '2024/logistics/INV-2024-001.json')"
        }
      },
      required: ["invoice_path"]
    }
  },
  {
    name: "search_invoices",
    description: "Searches for invoices matching specific criteria across the archive.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query string"
        },
        field: {
          type: "string",
          enum: ["invoice_id", "vendor", "amount"],
          description: "Field to search in (defaults to invoice_id)"
        }
      },
      required: ["query"]
    }
  },
  {
    name: "generate_report",
    description: "Generates an aggregated report for a specified period.",
    inputSchema: {
      type: "object",
      properties: {
        report_type: {
          type: "string",
          enum: ["monthly", "quarterly", "annual"],
          description: "Type of report to generate"
        },
        period: {
          type: "string",
          description: "Period identifier (e.g., '2024-Q1', '2024-01')"
        }
      },
      required: ["report_type", "period"]
    }
  }
];

// ============================================================================
// Request Handlers
// ============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;
    
    switch (name) {
      case "list_invoices": {
        const validated = ListInvoicesSchema.parse(args);
        const result = await listInvoices(validated);
        return { content: [{ type: "text", text: result }] };
      }
      
      case "get_invoice": {
        const validated = GetInvoiceSchema.parse(args);
        const result = await getInvoice(validated);
        return { content: [{ type: "text", text: result }] };
      }
      
      case "search_invoices": {
        const validated = SearchInvoicesSchema.parse(args);
        const result = await searchInvoices(validated);
        return { content: [{ type: "text", text: result }] };
      }
      
      case "generate_report": {
        const validated = GenerateReportSchema.parse(args);
        const result = await generateReport(validated);
        return { content: [{ type: "text", text: result }] };
      }
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Validation error: ${JSON.stringify(error.errors)}`);
    }
    throw error;
  }
});

// ============================================================================
// Server Initialization
// ============================================================================

async function main() {
  console.error("Initializing Legacy Invoice Management MCP Server...");
  
  await ensureDirectoryStructure();
  await generateSampleInvoices();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error("Server running on stdio transport");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});