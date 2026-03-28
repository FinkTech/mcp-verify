#!/bin/bash

# 2. Detect Regression in Insecure Server (v2.0.0)
# This script demonstrates automatic regression detection

set -e

echo "================================================"
echo "  Step 2: Detect Regression in Insecure Server"
echo "================================================"
echo ""

# Navigate to project root
cd "$(dirname "$0")/../.."

echo "⚠️  Starting INSECURE server (v2.0.0)..."
echo "   This version has command injection and path traversal vulnerabilities"
echo ""

echo "🔍 Scanning server and comparing with baseline..."
echo ""

# Run validation and compare with baseline
node dist/mcp-verify.js validate \
  stdio://node examples/regression-detection/demo-server-v2.js \
  --compare-baseline \
  --output ./examples/regression-detection/reports

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 2 ]; then
  echo "⛔ BLOCKING ISSUES DETECTED (Exit code: 2)"
  echo "   Critical vulnerabilities prevent deployment"
elif [ $EXIT_CODE -eq 1 ]; then
  echo "⚠️  WARNING (Exit code: 1)"
  echo "   Review required before deployment"
else
  echo "✅ NO DEGRADATION (Exit code: 0)"
  echo "   Safe to deploy"
fi

echo ""
echo "💡 Next steps:"
echo "   - Review the findings above"
echo "   - Check the HTML report: ./examples/regression-detection/reports/"
echo "   - View full history: node dist/mcp-verify.js history"
echo "   - Compare scans: ./3-compare-scans.sh"
echo ""
