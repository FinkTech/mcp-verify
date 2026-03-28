#!/bin/bash
#
# GitHub Repository Configuration Script
# Automatiza toda la configuración de FinkTech/mcp-verify
#
# Requisitos:
#   - GitHub CLI (gh) instalado y autenticado
#   - Permisos de admin en el repo
#
# Uso:
#   bash scripts/setup-github.sh
#

set -e  # Exit on error

REPO="FinkTech/mcp-verify"

echo "=================================="
echo "🚀 Configurando $REPO"
echo "=================================="

# Verificar que gh esté instalado
if ! command -v gh &> /dev/null; then
    echo "❌ ERROR: GitHub CLI (gh) no está instalado"
    echo "Instalá con: winget install --id GitHub.cli"
    exit 1
fi

# Verificar autenticación
if ! gh auth status &> /dev/null; then
    echo "❌ ERROR: No estás autenticado en GitHub"
    echo "Ejecutá: gh auth login"
    exit 1
fi

echo "✅ GitHub CLI configurado correctamente"
echo ""

# =============================================================================
# 1. HACER REPO PÚBLICO
# =============================================================================
echo "📢 1. Haciendo el repositorio público..."
gh repo edit $REPO --visibility public
echo "✅ Repositorio ahora es público"
echo ""

# =============================================================================
# 2. CONFIGURAR FEATURES
# =============================================================================
echo "⚙️ 2. Configurando features..."

# Habilitar Issues
gh repo edit $REPO --enable-issues

# Habilitar Discussions
gh api -X PUT /repos/$REPO/discussions -f enable=true 2>/dev/null || echo "⚠️ Discussions ya estaban habilitadas o hubo error"

# Habilitar auto-delete de head branches
gh api -X PATCH /repos/$REPO -f delete_branch_on_merge=true

# Deshabilitar Wiki
gh repo edit $REPO --enable-wiki=false

echo "✅ Features configuradas"
echo ""

# =============================================================================
# 3. CONFIGURAR DEFAULT BRANCH
# =============================================================================
echo "🌿 3. Configurando default branch a 'develop'..."

# Verificar que develop exista
if git ls-remote --heads origin develop | grep -q develop; then
    gh api -X PATCH /repos/$REPO -f default_branch=develop
    echo "✅ Default branch configurado a 'develop'"
else
    echo "⚠️ Branch 'develop' no existe todavía. Crealo primero:"
    echo "   git checkout -b develop"
    echo "   git push -u origin develop"
fi
echo ""

# =============================================================================
# 4. BRANCH PROTECTION - MAIN
# =============================================================================
echo "🛡️ 4. Configurando branch protection para 'main'..."

gh api -X PUT /repos/$REPO/branches/main/protection \
  -f required_status_checks[strict]=true \
  -f required_status_checks[contexts][]=ci \
  -f enforce_admins=true \
  -f required_pull_request_reviews[dismiss_stale_reviews]=true \
  -f required_pull_request_reviews[require_code_owner_reviews]=false \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f required_linear_history=true \
  -f allow_force_pushes=false \
  -f allow_deletions=false \
  -f lock_branch=false \
  -f required_conversation_resolution=true

echo "✅ Branch protection para 'main' configurada"
echo ""

# =============================================================================
# 5. BRANCH PROTECTION - DEVELOP
# =============================================================================
echo "🛡️ 5. Configurando branch protection para 'develop'..."

if git ls-remote --heads origin develop | grep -q develop; then
    gh api -X PUT /repos/$REPO/branches/develop/protection \
      -f required_status_checks[strict]=false \
      -f required_status_checks[contexts][]=ci \
      -f enforce_admins=false \
      -f required_pull_request_reviews[dismiss_stale_reviews]=false \
      -f required_pull_request_reviews[required_approving_review_count]=0 \
      -f allow_force_pushes=false \
      -f allow_deletions=false

    echo "✅ Branch protection para 'develop' configurada"
else
    echo "⚠️ Saltando - branch 'develop' no existe"
fi
echo ""

# =============================================================================
# 6. TOPICS (TAGS)
# =============================================================================
echo "🏷️ 6. Configurando topics..."

gh api -X PUT /repos/$REPO/topics \
  -f names[]="mcp" \
  -f names[]="security" \
  -f names[]="fuzzing" \
  -f names[]="typescript" \
  -f names[]="nodejs" \
  -f names[]="anthropic" \
  -f names[]="model-context-protocol" \
  -f names[]="security-scanner" \
  -f names[]="vulnerability-scanner" \
  -f names[]="llm-security" \
  -f names[]="ai-security" \
  -f names[]="devsecops" \
  -f names[]="static-analysis" \
  -f names[]="dynamic-analysis" \
  -f names[]="ci-cd" \
  -f names[]="mcp-server" \
  -f names[]="claude" \
  -f names[]="security-testing"

echo "✅ Topics configurados"
echo ""

# =============================================================================
# 7. LABELS
# =============================================================================
echo "🏷️ 7. Creando labels personalizados..."

# Crear labels si no existen
gh label create "security" --description "Security-related issue" --color "d73a4a" --force || true
gh label create "fuzzing" --description "Fuzzing engine related" --color "0075ca" --force || true
gh label create "good first issue" --description "Good for newcomers" --color "7057ff" --force || true
gh label create "help wanted" --description "Extra attention needed" --color "008672" --force || true
gh label create "breaking change" --description "Breaking API changes" --color "d93f0b" --force || true
gh label create "enhancement" --description "New feature request" --color "a2eeef" --force || true

echo "✅ Labels creados"
echo ""

# =============================================================================
# 8. ISSUE TEMPLATES
# =============================================================================
echo "📝 8. Issue templates..."
echo "⚠️ Los templates ya están en .github/ISSUE_TEMPLATE/"
echo "   Se subirán automáticamente con git push"
echo ""

# =============================================================================
# 9. CONFIGURAR MERGE SETTINGS
# =============================================================================
echo "🔀 9. Configurando merge settings..."

gh api -X PATCH /repos/$REPO \
  -f allow_merge_commit=true \
  -f allow_squash_merge=true \
  -f allow_rebase_merge=false \
  -f delete_branch_on_merge=true

echo "✅ Merge settings configurados"
echo ""

# =============================================================================
# RESUMEN
# =============================================================================
echo "=================================="
echo "✅ CONFIGURACIÓN COMPLETA"
echo "=================================="
echo ""
echo "✅ Repo es público"
echo "✅ Default branch: develop"
echo "✅ Branch protection: main + develop"
echo "✅ Topics configurados"
echo "✅ Labels creados"
echo "✅ Merge settings configurados"
echo ""
echo "⚠️ PENDIENTE (manual):"
echo "   1. Secrets para CI/CD:"
echo "      → https://github.com/$REPO/settings/secrets/actions"
echo "      → Agregar: ANTHROPIC_API_KEY, GOOGLE_API_KEY"
echo "      → Agregar: CRONOS_TOKEN, LEX_TOKEN, AUDITOR_TOKEN"
echo ""
echo "   2. Issue templates:"
echo "      → https://github.com/$REPO/issues/templates/edit"
echo "      → Click 'Set up templates'"
echo ""
echo "   3. Discussions:"
echo "      → https://github.com/$REPO/discussions"
echo "      → Click 'Set up discussions'"
echo ""
echo "🎉 Script completado exitosamente!"
