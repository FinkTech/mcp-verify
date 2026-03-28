#!/bin/bash

# 1. Create Baseline from Secure Server (v1.0.0)
# This script demonstrates how to create a baseline scan

set -e

echo "================================================"
echo "  Step 1: Create Baseline from Secure Server"
echo "================================================"
echo ""

# Navigate to project root
cd "$(dirname "$0")/../.."

echo "📦 Building mcp-verify..."
npm run build > /dev/null 2>&1
echo "✓ Build complete"
echo ""

echo "🚀 Starting secure server (v1.0.0)..."
echo "   This version has proper input validation and no vulnerabilities"
echo ""

# Run validation and set baseline
echo "🔍 Scanning server and creating baseline..."
node dist/mcp-verify.js validate \
  stdio://node examples/regression-detection/demo-server.js \
  --set-baseline \
  --output ./examples/regression-detection/reports

echo ""
echo "✅ Baseline created successfully!"
echo ""
echo "📊 View the baseline:"
echo "   node dist/mcp-verify.js history"
echo ""
echo "💡 Next step:"
echo "   ./2-detect-regression.sh"
echo ""
