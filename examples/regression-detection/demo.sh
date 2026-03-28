#!/bin/bash

# Interactive Demo: Regression Detection Workflow
# This script demonstrates the complete regression detection workflow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Navigate to project root
cd "$(dirname "$0")/../.."

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║        🔄 Regression Detection - Interactive Demo         ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if built
if [ ! -f "dist/mcp-verify.js" ]; then
  echo -e "${YELLOW}📦 Building mcp-verify...${NC}"
  npm run build > /dev/null 2>&1
  echo -e "${GREEN}✓ Build complete${NC}"
  echo ""
fi

echo "This demo will:"
echo "  1. Create a baseline from a secure server (v1.0.0)"
echo "  2. Introduce vulnerabilities in v2.0.0"
echo "  3. Detect the regression automatically"
echo "  4. Show comparison and history"
echo ""

read -p "Press Enter to start..."
echo ""

# ============================================
# STEP 1: Create Baseline
# ============================================

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  STEP 1: Create Baseline from Secure Server (v1.0.0)      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo -e "${BLUE}📝 Server Info:${NC}"
echo "   Name:    demo-mcp-server"
echo "   Version: 1.0.0"
echo "   Status:  ✅ Secure (proper validation, no vulnerabilities)"
echo ""

echo -e "${YELLOW}🔍 Scanning and creating baseline...${NC}"
echo ""

node dist/mcp-verify.js validate \
  stdio://node examples/regression-detection/demo-server.js \
  --set-baseline \
  --output ./examples/regression-detection/reports \
  > /tmp/baseline-scan.log 2>&1 || true

echo ""
echo -e "${GREEN}✅ Baseline created successfully!${NC}"
echo ""

read -p "Press Enter to continue to Step 2..."
echo ""

# ============================================
# STEP 2: Detect Regression
# ============================================

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  STEP 2: Detect Regression in Insecure Server (v2.0.0)    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo -e "${BLUE}📝 Server Info:${NC}"
echo "   Name:    demo-mcp-server"
echo "   Version: 2.0.0"
echo "   Status:  ❌ Insecure (command injection, path traversal)"
echo ""

echo -e "${BLUE}🆕 New Features (with vulnerabilities):${NC}"
echo "   • execute_command - ⚠️  Command injection risk"
echo "   • read_file       - ⚠️  Path traversal risk"
echo ""

echo -e "${YELLOW}🔍 Scanning and comparing with baseline...${NC}"
echo ""

# Run validation and capture exit code
node dist/mcp-verify.js validate \
  stdio://node examples/regression-detection/demo-server-v2.js \
  --compare-baseline \
  --output ./examples/regression-detection/reports

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 2 ]; then
  echo -e "${RED}⛔ BLOCKING ISSUES DETECTED (Exit code: 2)${NC}"
  echo "   Critical vulnerabilities prevent deployment"
elif [ $EXIT_CODE -eq 1 ]; then
  echo -e "${YELLOW}⚠️  WARNING (Exit code: 1)${NC}"
  echo "   Review required before deployment"
else
  echo -e "${GREEN}✅ NO DEGRADATION (Exit code: 0)${NC}"
  echo "   Safe to deploy"
fi

echo ""
read -p "Press Enter to view scan history..."
echo ""

# ============================================
# STEP 3: View History
# ============================================

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  STEP 3: View Scan History & Trend Analysis               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

node dist/mcp-verify.js history --trend

echo ""
read -p "Press Enter to see manual comparison..."
echo ""

# ============================================
# STEP 4: Manual Comparison
# ============================================

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  STEP 4: Manual Scan Comparison                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo -e "${BLUE}Getting scan IDs...${NC}"
echo ""

# Get the two most recent scans
SCANS=$(node dist/mcp-verify.js history --limit 2 --json 2>/dev/null || node dist/mcp-verify.js history --limit 2)

# Extract scan IDs (simplified - assumes specific format)
SCAN_IDS=$(ls -t .mcp-verify/history/*.json 2>/dev/null | head -2 | xargs -n1 basename | sed 's/.json//')

if [ $(echo "$SCAN_IDS" | wc -l) -ge 2 ]; then
  SCAN1=$(echo "$SCAN_IDS" | sed -n 1p)
  SCAN2=$(echo "$SCAN_IDS" | sed -n 2p)

  echo -e "${YELLOW}Comparing scans:${NC}"
  echo "   Baseline: $SCAN1"
  echo "   Current:  $SCAN2"
  echo ""

  node dist/mcp-verify.js diff "$SCAN1" "$SCAN2" 2>/dev/null || echo "Run history command to see scan IDs"
else
  echo "Not enough scans for comparison"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                     Demo Complete! 🎉                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo -e "${GREEN}✅ You've learned how to:${NC}"
echo "   • Create baselines from secure releases"
echo "   • Detect regressions automatically"
echo "   • View scan history and trends"
echo "   • Compare specific scans"
echo ""

echo -e "${BLUE}📚 Next Steps:${NC}"
echo "   • Integrate into CI/CD: ./ci-cd/github-actions.yml"
echo "   • Add pre-commit hook: ./ci-cd/pre-commit-hook.sh"
echo "   • Read full guide: ../../REGRESSION-DETECTION.md"
echo ""

echo -e "${YELLOW}🔧 Available Commands:${NC}"
echo "   node dist/mcp-verify.js history           # View all scans"
echo "   node dist/mcp-verify.js history --trend   # Show trend analysis"
echo "   node dist/mcp-verify.js diff <A> <B>      # Compare two scans"
echo ""

echo -e "${BLUE}📁 Reports Location:${NC}"
echo "   ./examples/regression-detection/reports/"
echo ""

echo -e "${GREEN}Thank you for trying mcp-verify! 🚀${NC}"
echo ""
