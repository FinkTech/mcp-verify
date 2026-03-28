#!/bin/bash

# 4. View Scan History & Trend Analysis
# This script demonstrates history management and trend analysis

set -e

echo "================================================"
echo "  Step 4: View Scan History & Trend Analysis"
echo "================================================"
echo ""

# Navigate to project root
cd "$(dirname "$0")/../.."

echo "📋 All Scans (last 10):"
echo ""
node dist/mcp-verify.js history --limit 10

echo ""
echo "================================================"
echo ""

echo "📈 Trend Analysis:"
echo ""
node dist/mcp-verify.js history --trend

echo ""
echo "================================================"
echo ""

echo "🔍 Filter by server:"
echo ""
node dist/mcp-verify.js history --server demo-mcp-server --limit 5

echo ""
echo "💡 Additional commands:"
echo "   - View all scans: node dist/mcp-verify.js history"
echo "   - Show more scans: node dist/mcp-verify.js history --limit 20"
echo "   - Clear history: rm -rf .mcp-verify/history/"
echo ""
