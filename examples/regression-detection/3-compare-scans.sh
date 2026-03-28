#!/bin/bash

# 3. Compare Two Specific Scans
# This script shows how to manually compare any two scans

set -e

echo "================================================"
echo "  Step 3: Compare Two Specific Scans"
echo "================================================"
echo ""

# Navigate to project root
cd "$(dirname "$0")/../.."

echo "📋 Listing available scans..."
echo ""

node dist/mcp-verify.js history

echo ""
echo "📊 To compare two scans, copy their IDs from above and run:"
echo ""
echo "   node dist/mcp-verify.js diff <scan_id_1> <scan_id_2>"
echo ""
echo "Example:"
echo "   node dist/mcp-verify.js diff scan_2025-01-21T10-00-00_abc123 scan_2025-01-21T11-00-00_def456"
echo ""
echo "💡 Tip: Use --json flag for machine-readable output"
echo "   node dist/mcp-verify.js diff <scan_1> <scan_2> --json"
echo ""
