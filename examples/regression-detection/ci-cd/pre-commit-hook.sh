#!/bin/bash

# Git Pre-commit Hook for MCP Security
#
# This hook runs before every commit and checks for security regressions
# in your MCP server code.
#
# Installation:
#   1. Copy this file to: .git/hooks/pre-commit
#   2. Make it executable: chmod +x .git/hooks/pre-commit
#
# To bypass (not recommended):
#   git commit --no-verify

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo ""
echo "🔍 Running MCP security check..."
echo ""

# Check if MCP server files were modified
if ! git diff --cached --name-only | grep -qE '(src/mcp-server|mcp-server/)'; then
  echo -e "${GREEN}✓ No MCP server files modified, skipping security check${NC}"
  exit 0
fi

echo "📝 MCP server files modified, running security validation..."
echo ""

# Check if mcp-verify is available
if ! command -v mcp-verify &> /dev/null; then
  echo -e "${YELLOW}⚠️  mcp-verify not found, trying local build...${NC}"

  if [ -f "dist/mcp-verify.js" ]; then
    MCP_VERIFY="node dist/mcp-verify.js"
  else
    echo -e "${RED}❌ mcp-verify not installed and no local build found${NC}"
    echo "   Install: npm install -g mcp-verify"
    echo "   Or bypass: git commit --no-verify"
    exit 1
  fi
else
  MCP_VERIFY="mcp-verify"
fi

# Determine MCP server location
MCP_SERVER_PATH=""

if [ -d "src/mcp-server" ]; then
  MCP_SERVER_PATH="src/mcp-server"
elif [ -d "mcp-server" ]; then
  MCP_SERVER_PATH="mcp-server"
elif [ -f "server.js" ]; then
  MCP_SERVER_PATH="server.js"
else
  echo -e "${YELLOW}⚠️  Could not find MCP server location${NC}"
  echo "   Skipping security check"
  exit 0
fi

# Run security check with baseline comparison
echo "🔒 Running security regression check..."
echo ""

$MCP_VERIFY validate "$MCP_SERVER_PATH" \
  --compare-baseline \
  --output ./reports

EXIT_CODE=$?

echo ""

# Handle exit codes
if [ $EXIT_CODE -eq 2 ]; then
  echo -e "${RED}⛔ COMMIT BLOCKED: Critical security issues detected${NC}"
  echo ""
  echo "   Critical vulnerabilities found that must be fixed before commit."
  echo "   Review the security report above and fix the issues."
  echo ""
  echo "   To bypass (NOT recommended):"
  echo "   git commit --no-verify"
  echo ""
  exit 1

elif [ $EXIT_CODE -eq 1 ]; then
  echo -e "${YELLOW}⚠️  WARNING: Security degradation detected${NC}"
  echo ""
  echo "   Your changes introduced security warnings."
  echo "   Review the findings above before committing."
  echo ""

  # Optional: Ask for confirmation
  read -p "   Do you want to commit anyway? (y/N) " -n 1 -r
  echo ""

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Commit cancelled${NC}"
    exit 1
  fi

  echo -e "${YELLOW}Proceeding with commit (warnings ignored)${NC}"
  echo ""

else
  echo -e "${GREEN}✅ No security degradation detected${NC}"
  echo ""
fi

# Save scan to history
echo "💾 Saving scan to history..."
$MCP_VERIFY validate "$MCP_SERVER_PATH" --save > /dev/null 2>&1 || true

echo -e "${GREEN}✓ Security check complete${NC}"
echo ""

exit 0
