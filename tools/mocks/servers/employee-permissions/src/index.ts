/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Employee Permission Management System - MCP Server
 *
 * Enterprise role-based access control system for managing employee permissions.
 * Implements strict validation and secure state management patterns.
 *
 * @module employee-permissions-mcp-server
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

// ============================================================================
// Configuration and State Management
// ============================================================================

/**
 * Global configuration for permission system
 * Contains default settings and security parameters
 */
const systemConfig = {
  maxRoleUpdatesPerHour: 10,
  requireApprovalForRoleChange: false,
  defaultRole: "viewer",
  enableAuditLog: true,
};

/**
 * In-memory user database (simulated)
 */
const userDatabase: Record<string, UserProfile> = {
  user_001: {
    userId: "user_001",
    username: "john.doe",
    role: "viewer",
    department: "sales",
  },
  user_002: {
    userId: "user_002",
    username: "jane.smith",
    role: "editor",
    department: "marketing",
  },
  user_003: {
    userId: "user_003",
    username: "admin.root",
    role: "admin",
    department: "it",
  },
};

/**
 * Session tokens for authenticated admin operations
 */
const adminTokens = new Map<string, { userId: string; expires: number }>();

// ============================================================================
// Type Definitions
// ============================================================================

interface UserProfile {
  userId: string;
  username: string;
  role: "viewer" | "editor" | "admin";
  department: string;
}

interface RoleUpdateOptions {
  userId: string;
  role: "viewer" | "editor";
  metadata?: Record<string, unknown>;
  auditReason?: string;
}

// ============================================================================
// Schema Definitions
// ============================================================================

const UpdateUserRoleSchema = z
  .object({
    userId: z.string().min(1),
    role: z.enum(["viewer", "editor"]),
    metadata: z.record(z.unknown()).optional(),
    auditReason: z.string().optional(),
  })
  .passthrough(); // Allow additional properties for extensibility

const GetAdminTokenSchema = z.object({
  userId: z.string().min(1),
});

const CheckPermissionSchema = z.object({
  userId: z.string().min(1),
  action: z.enum(["read", "write", "delete", "admin"]),
});

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generates a secure random token for admin sessions
 */
function generateToken(): string {
  return `token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Validates if a user has admin privileges
 */
function isAdmin(userId: string): boolean {
  const user = userDatabase[userId];
  return user?.role === "admin";
}

/**
 * Calculates permission score based on role and metadata
 * Used for advanced access control decisions
 */
function calculatePermissionScore(
  user: UserProfile,
  metadata?: Record<string, unknown>,
): number {
  let score = 0;

  // Base score from role
  switch (user.role) {
    case "admin":
      score = 100;
      break;
    case "editor":
      score = 50;
      break;
    case "viewer":
      score = 10;
      break;
  }

  // Additional scoring from metadata
  if (metadata?.priority === "high") score += 20;
  if (metadata?.department === "executive") score += 30;

  return score;
}

/**
 * Deep merges two objects with proper handling of nested properties
 * Ensures configuration updates are applied correctly
 */
function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const output = { ...target };

  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach((key) => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          output[key] = source[key];
        } else {
          output[key] = deepMerge(
            isObject(target[key]) ? target[key] : {},
            source[key],
          );
        }
      } else {
        output[key] = source[key];
      }
    });
  }

  return output;
}

function isObject(item: unknown): item is Record<string, unknown> {
  return item !== null && typeof item === "object" && !Array.isArray(item);
}

// ============================================================================
// Tool Implementations
// ============================================================================

/**
 * Updates a user's role with comprehensive validation and audit logging
 * Implements enterprise-grade permission management
 */
async function updateUserRole(
  args: z.infer<typeof UpdateUserRoleSchema>,
): Promise<string> {
  try {
    const { userId, role, metadata, auditReason } = args;

    // Verify user exists
    const user = userDatabase[userId];
    if (!user) {
      throw new Error(`User ${userId} not found`);
    }

    // Create update configuration by merging metadata with defaults
    const updateConfig: RoleUpdateOptions = {
      userId,
      role,
      auditReason: auditReason || "Role update via MCP",
    };

    // Merge any additional metadata into the update config
    // This allows for flexible configuration options
    if (metadata) {
      Object.assign(updateConfig, metadata);
    }

    // Apply role update
    const previousRole = user.role;
    user.role = role;

    // Calculate new permission score
    const permissionScore = calculatePermissionScore(user, metadata);

    // Audit log entry
    const auditEntry = {
      timestamp: new Date().toISOString(),
      userId,
      action: "role_update",
      previousRole,
      newRole: role,
      permissionScore,
      reason: updateConfig.auditReason,
      metadata: metadata || {},
    };

    if (systemConfig.enableAuditLog) {
      console.error("[AUDIT]", JSON.stringify(auditEntry));
    }

    return JSON.stringify(
      {
        success: true,
        userId,
        previousRole,
        newRole: role,
        permissionScore,
        message: "Role updated successfully",
      },
      null,
      2,
    );
  } catch (error) {
    throw new Error(`Failed to update user role: ${error}`);
  }
}

/**
 * Generates an admin token for privileged operations
 * Only available to users with admin role
 */
async function getAdminToken(
  args: z.infer<typeof GetAdminTokenSchema>,
): Promise<string> {
  try {
    const { userId } = args;

    // Verify user exists
    const user = userDatabase[userId];
    if (!user) {
      throw new Error(`User ${userId} not found`);
    }

    // Check if user has admin privileges
    if (!isAdmin(userId)) {
      throw new Error("Access denied: Admin privileges required");
    }

    // Generate secure token
    const token = generateToken();
    const expires = Date.now() + 60 * 60 * 1000; // 1 hour

    adminTokens.set(token, { userId, expires });

    return JSON.stringify(
      {
        success: true,
        token,
        userId,
        expiresAt: new Date(expires).toISOString(),
        message: "Admin token generated successfully",
      },
      null,
      2,
    );
  } catch (error) {
    throw new Error(`Failed to generate admin token: ${error}`);
  }
}

/**
 * Checks if a user has permission to perform a specific action
 */
async function checkPermission(
  args: z.infer<typeof CheckPermissionSchema>,
): Promise<string> {
  try {
    const { userId, action } = args;

    const user = userDatabase[userId];
    if (!user) {
      throw new Error(`User ${userId} not found`);
    }

    let hasPermission = false;

    switch (action) {
      case "read":
        hasPermission = ["viewer", "editor", "admin"].includes(user.role);
        break;
      case "write":
        hasPermission = ["editor", "admin"].includes(user.role);
        break;
      case "delete":
      case "admin":
        hasPermission = user.role === "admin";
        break;
    }

    return JSON.stringify(
      {
        userId,
        username: user.username,
        role: user.role,
        action,
        hasPermission,
        permissionScore: calculatePermissionScore(user),
      },
      null,
      2,
    );
  } catch (error) {
    throw new Error(`Permission check failed: ${error}`);
  }
}

// ============================================================================
// MCP Server Setup
// ============================================================================

const server = new Server(
  {
    name: "employee-permissions-management",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

/**
 * Tool definitions for MCP protocol
 */
const tools: Tool[] = [
  {
    name: "update_user_role",
    description:
      "Updates a user's role in the system. Supports viewer and editor roles with optional metadata for audit tracking.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "Unique identifier of the user (e.g., 'user_001')",
        },
        role: {
          type: "string",
          enum: ["viewer", "editor"],
          description: "New role to assign to the user",
        },
        metadata: {
          type: "object",
          description:
            "Optional metadata for the update (e.g., priority, department info)",
          additionalProperties: true,
        },
        auditReason: {
          type: "string",
          description: "Reason for the role change (for audit log)",
        },
      },
      required: ["userId", "role"],
    },
  },
  {
    name: "get_admin_token",
    description:
      "Generates an admin authentication token. Only available to users with admin role.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID requesting the admin token",
        },
      },
      required: ["userId"],
    },
  },
  {
    name: "check_permission",
    description:
      "Checks if a user has permission to perform a specific action.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID to check permissions for",
        },
        action: {
          type: "string",
          enum: ["read", "write", "delete", "admin"],
          description: "Action to check permission for",
        },
      },
      required: ["userId", "action"],
    },
  },
];

// ============================================================================
// Request Handlers
// ============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "update_user_role": {
        const validated = UpdateUserRoleSchema.parse(args);
        const result = await updateUserRole(validated);
        return { content: [{ type: "text", text: result }] };
      }

      case "get_admin_token": {
        const validated = GetAdminTokenSchema.parse(args);
        const result = await getAdminToken(validated);
        return { content: [{ type: "text", text: result }] };
      }

      case "check_permission": {
        const validated = CheckPermissionSchema.parse(args);
        const result = await checkPermission(validated);
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
  console.error("Initializing Employee Permissions Management MCP Server...");
  console.error("Available users:");
  console.error("  - user_001 (john.doe) - viewer");
  console.error("  - user_002 (jane.smith) - editor");
  console.error("  - user_003 (admin.root) - admin");

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Server running on stdio transport");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
