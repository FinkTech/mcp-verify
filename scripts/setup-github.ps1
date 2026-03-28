# GitHub Repository Configuration Script (PowerShell)
# Automatiza toda la configuracion de FinkTech/mcp-verify
#
# Requisitos:
#   - GitHub CLI (gh) instalado y autenticado
#   - Permisos de admin en el repo
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File scripts\setup-github.ps1
#

$ErrorActionPreference = "Stop"

$REPO = "FinkTech/mcp-verify"

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "[*] Configurando $REPO" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Verificar que gh este instalado
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "[X] ERROR: GitHub CLI (gh) no esta instalado" -ForegroundColor Red
    Write-Host "Instala con: winget install --id GitHub.cli" -ForegroundColor Yellow
    exit 1
}

# Verificar autenticacion
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] ERROR: No estas autenticado en GitHub" -ForegroundColor Red
    Write-Host "Ejecuta: gh auth login" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] GitHub CLI configurado correctamente" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 1. VISIBILIDAD DEL REPO (COMENTADO - NO HACER PUBLICO TODAVIA)
# =============================================================================
# Write-Host "[1/8] Haciendo el repositorio publico..." -ForegroundColor Yellow
# gh repo edit $REPO --visibility public
# Write-Host "[OK] Repositorio ahora es publico" -ForegroundColor Green
Write-Host "[1/8] Saltando cambio de visibilidad (repo se mantiene privado)" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 2. CONFIGURAR FEATURES
# =============================================================================
Write-Host "[2/8] Configurando features..." -ForegroundColor Yellow

# Habilitar Issues
gh repo edit $REPO --enable-issues

# Habilitar auto-delete de head branches
gh api -X PATCH /repos/$REPO -f delete_branch_on_merge=true

# Deshabilitar Wiki
gh repo edit $REPO --enable-wiki=false

Write-Host "[OK] Features configuradas" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 3. CONFIGURAR DEFAULT BRANCH
# =============================================================================
Write-Host "[3/8] Configurando default branch a 'develop'..." -ForegroundColor Yellow

# Verificar que develop exista
$developExists = git ls-remote --heads origin develop
if ($developExists) {
    gh api -X PATCH /repos/$REPO -f default_branch=develop
    Write-Host "[OK] Default branch configurado a 'develop'" -ForegroundColor Green
} else {
    Write-Host "[!] Branch 'develop' no existe todavia. Crealo primero:" -ForegroundColor Yellow
    Write-Host "   git checkout -b develop" -ForegroundColor Cyan
    Write-Host "   git push -u origin develop" -ForegroundColor Cyan
}
Write-Host ""

# =============================================================================
# 4. BRANCH PROTECTION - MAIN
# =============================================================================
Write-Host "[4/8] Configurando branch protection para 'main'..." -ForegroundColor Yellow

$mainProtection = @{
    required_status_checks = @{
        strict = $true
        contexts = @("ci")
    }
    enforce_admins = $true
    required_pull_request_reviews = @{
        dismiss_stale_reviews = $true
        require_code_owner_reviews = $false
        required_approving_review_count = 1
    }
    required_linear_history = $true
    allow_force_pushes = $false
    allow_deletions = $false
    lock_branch = $false
    required_conversation_resolution = $true
} | ConvertTo-Json -Depth 10

gh api -X PUT /repos/$REPO/branches/main/protection --input - <<< $mainProtection

Write-Host "[OK] Branch protection para 'main' configurada" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 5. BRANCH PROTECTION - DEVELOP
# =============================================================================
Write-Host "[5/8] Configurando branch protection para 'develop'..." -ForegroundColor Yellow

$developExists = git ls-remote --heads origin develop
if ($developExists) {
    $developProtection = @{
        required_status_checks = @{
            strict = $false
            contexts = @("ci")
        }
        enforce_admins = $false
        required_pull_request_reviews = @{
            dismiss_stale_reviews = $false
            required_approving_review_count = 0
        }
        allow_force_pushes = $false
        allow_deletions = $false
    } | ConvertTo-Json -Depth 10

    gh api -X PUT /repos/$REPO/branches/develop/protection --input - <<< $developProtection

    Write-Host "[OK] Branch protection para 'develop' configurada" -ForegroundColor Green
} else {
    Write-Host "[!] Saltando - branch 'develop' no existe" -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 6. TOPICS (TAGS)
# =============================================================================
Write-Host "[6/8] Configurando topics..." -ForegroundColor Yellow

$topics = @{
    names = @(
        "mcp",
        "security",
        "fuzzing",
        "typescript",
        "nodejs",
        "anthropic",
        "model-context-protocol",
        "security-scanner",
        "vulnerability-scanner",
        "llm-security",
        "ai-security",
        "devsecops",
        "static-analysis",
        "dynamic-analysis",
        "ci-cd",
        "mcp-server",
        "claude",
        "security-testing"
    )
} | ConvertTo-Json

gh api -X PUT /repos/$REPO/topics --input - <<< $topics

Write-Host "[OK] Topics configurados" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 7. LABELS
# =============================================================================
Write-Host "[7/8] Creando labels personalizados..." -ForegroundColor Yellow

gh label create "security" --description "Security-related issue" --color "d73a4a" --force 2>$null
gh label create "fuzzing" --description "Fuzzing engine related" --color "0075ca" --force 2>$null
gh label create "good first issue" --description "Good for newcomers" --color "7057ff" --force 2>$null
gh label create "help wanted" --description "Extra attention needed" --color "008672" --force 2>$null
gh label create "breaking change" --description "Breaking API changes" --color "d93f0b" --force 2>$null
gh label create "enhancement" --description "New feature request" --color "a2eeef" --force 2>$null

Write-Host "[OK] Labels creados" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 8. CONFIGURAR MERGE SETTINGS
# =============================================================================
Write-Host "[8/8] Configurando merge settings..." -ForegroundColor Yellow

gh api -X PATCH /repos/$REPO `
  -f allow_merge_commit=true `
  -f allow_squash_merge=true `
  -f allow_rebase_merge=false `
  -f delete_branch_on_merge=true

Write-Host "[OK] Merge settings configurados" -ForegroundColor Green
Write-Host ""

# =============================================================================
# RESUMEN
# =============================================================================
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "[OK] CONFIGURACION COMPLETA" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[OK] Repo se mantiene privado" -ForegroundColor Cyan
Write-Host "[OK] Default branch: develop" -ForegroundColor Green
Write-Host "[OK] Branch protection: main + develop" -ForegroundColor Green
Write-Host "[OK] Topics configurados" -ForegroundColor Green
Write-Host "[OK] Labels creados" -ForegroundColor Green
Write-Host "[OK] Merge settings configurados" -ForegroundColor Green
Write-Host ""
Write-Host "[!] PENDIENTE (manual):" -ForegroundColor Yellow
Write-Host "   1. Secrets para CI/CD:"
Write-Host "      -> https://github.com/$REPO/settings/secrets/actions"
Write-Host "      -> Agregar: ANTHROPIC_API_KEY, GOOGLE_API_KEY"
Write-Host "      -> Agregar: CRONOS_TOKEN, LEX_TOKEN, AUDITOR_TOKEN"
Write-Host ""
Write-Host "   2. Issue templates:"
Write-Host "      -> https://github.com/$REPO/issues/templates/edit"
Write-Host "      -> Click 'Set up templates'"
Write-Host ""
Write-Host "   3. Discussions:"
Write-Host "      -> https://github.com/$REPO/discussions"
Write-Host "      -> Click 'Set up discussions'"
Write-Host ""
Write-Host "[*] Script completado exitosamente!" -ForegroundColor Green
