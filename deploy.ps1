#!/usr/bin/env pwsh
# ============================================================
# HaruStream PRO — Automated Deployment Script
# Target: Cloudflare Second Account (via API Token)
# Run: .\deploy.ps1
# ============================================================

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ── COLORS ──────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-Ok     { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Fail   { param($msg) Write-Host "  [!!] $msg" -ForegroundColor Red }
function Write-Info   { param($msg) Write-Host "  [-]  $msg" -ForegroundColor DarkGray }
function Write-Banner {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║   HaruStream PRO — Deploy Script      ║" -ForegroundColor Magenta
    Write-Host "  ║   Target: Cloudflare Second Account   ║" -ForegroundColor Magenta
    Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
}

Write-Banner

# ── STEP 0: Check Node & Wrangler ───────────────────────────
Write-Step "Checking prerequisites..."

try {
    $nodeVer = node --version 2>&1
    Write-Ok "Node.js: $nodeVer"
} catch {
    Write-Fail "Node.js not found! Install from https://nodejs.org"
    exit 1
}

# Install wrangler locally if not present
if (-not (Test-Path ".\node_modules\.bin\wrangler.cmd") -and -not (Test-Path ".\node_modules\.bin\wrangler")) {
    Write-Info "Installing wrangler locally..."
    npm install --silent
    Write-Ok "Wrangler installed."
} else {
    Write-Ok "Wrangler found in node_modules."
}

$wrangler = "npx wrangler"

# ── STEP 1: Collect Credentials ─────────────────────────────
Write-Step "Cloudflare Second Account Credentials"
Write-Info "Get API Token: https://dash.cloudflare.com/profile/api-tokens"
Write-Info "  -> Create Token -> 'Edit Cloudflare Workers' template"
Write-Info "Get Account ID: Cloudflare Dashboard -> Right sidebar"
Write-Host ""

# Check if credentials already saved in .env.deploy
$envFile = ".\.env.deploy"
if (Test-Path $envFile) {
    Write-Info "Found saved credentials in .env.deploy — loading..."
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.+)$") {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

# Read or prompt for credentials
if (-not $env:CLOUDFLARE_API_TOKEN) {
    $token = Read-Host "  Paste your CF API Token (second account)"
    $env:CLOUDFLARE_API_TOKEN = $token.Trim()
}
if (-not $env:CLOUDFLARE_ACCOUNT_ID) {
    $accountId = Read-Host "  Paste your CF Account ID (second account)"
    $env:CLOUDFLARE_ACCOUNT_ID = $accountId.Trim()
}

# Prompt for JWT secret
if (-not $env:HS_JWT_SECRET) {
    $jwtSecret = Read-Host "  Enter JWT_SECRET (any long random string, min 32 chars)"
    $env:HS_JWT_SECRET = $jwtSecret.Trim()
}

# Save for next run
$saveChoice = Read-Host "  Save credentials to .env.deploy for future runs? [y/N]"
if ($saveChoice -eq 'y' -or $saveChoice -eq 'Y') {
    @"
CLOUDFLARE_API_TOKEN=$($env:CLOUDFLARE_API_TOKEN)
CLOUDFLARE_ACCOUNT_ID=$($env:CLOUDFLARE_ACCOUNT_ID)
HS_JWT_SECRET=$($env:HS_JWT_SECRET)
"@ | Set-Content $envFile -Encoding UTF8
    Write-Ok "Credentials saved to .env.deploy (add to .gitignore!)"

    # Auto-add to .gitignore
    $gitignore = ".\.gitignore"
    if (-not (Test-Path $gitignore) -or -not (Get-Content $gitignore | Select-String ".env.deploy")) {
        Add-Content $gitignore "`n.env.deploy"
        Write-Ok ".env.deploy added to .gitignore"
    }
}

Write-Ok "Credentials loaded."

# ── STEP 2: Verify Token ─────────────────────────────────────
Write-Step "Verifying Cloudflare API Token..."
try {
    $verifyResult = npx wrangler whoami 2>&1
    if ($verifyResult -match "You are logged in") {
        Write-Ok "Token valid: $($verifyResult | Select-String 'You are logged in.*')"
    } else {
        Write-Info "Token response: $verifyResult"
    }
} catch {
    Write-Info "Verify skipped (token will be validated on first operation)"
}

# ── STEP 3: Create D1 Database ──────────────────────────────
Write-Step "Creating D1 Database 'haru-stream-db'..."

$dbName = "haru-stream-db"
$dbOutput = npx wrangler d1 create $dbName --account-id $env:CLOUDFLARE_ACCOUNT_ID 2>&1
$dbOutputStr = $dbOutput -join "`n"

Write-Info "D1 create output:"
Write-Host $dbOutputStr -ForegroundColor DarkGray

# Extract database_id from output
$dbIdMatch = [regex]::Match($dbOutputStr, 'database_id\s*=\s*"([a-f0-9\-]{36})"')
if ($dbIdMatch.Success) {
    $dbId = $dbIdMatch.Groups[1].Value
    Write-Ok "D1 Database created! ID: $dbId"
} else {
    # Maybe it already exists — try to list and find it
    Write-Info "Could not parse DB ID from create output. Trying to find existing database..."
    $listOutput = npx wrangler d1 list --account-id $env:CLOUDFLARE_ACCOUNT_ID 2>&1
    $listStr = $listOutput -join "`n"
    Write-Host $listStr -ForegroundColor DarkGray

    $listMatch = [regex]::Match($listStr, "$dbName\s+\|\s+([a-f0-9\-]{36})")
    if (-not $listMatch.Success) {
        # Try alternate format
        $listMatch = [regex]::Match($listStr, "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})")
    }

    if ($listMatch.Success) {
        $dbId = $listMatch.Groups[1].Value
        Write-Ok "Found existing D1 database: $dbId"
    } else {
        Write-Fail "Could not determine D1 Database ID. Please check output above and update wrangler.toml manually."
        $dbId = Read-Host "  Paste the Database ID manually"
        $dbId = $dbId.Trim()
    }
}

# ── STEP 4: Update wrangler.toml with DB ID ─────────────────
Write-Step "Updating wrangler.toml with Database ID..."

$tomlPath = ".\wrangler.toml"
$tomlContent = Get-Content $tomlPath -Raw
$tomlContent = $tomlContent -replace 'database_id\s*=\s*"REPLACE_WITH_YOUR_D1_DATABASE_ID"', "database_id = `"$dbId`""
$tomlContent = $tomlContent -replace 'database_id\s*=\s*"REPLACE_WITH_YOUR_D1_DEV_DATABASE_ID"', "database_id = `"$dbId`""
Set-Content $tomlPath $tomlContent -Encoding UTF8
Write-Ok "wrangler.toml updated with database_id: $dbId"

# ── STEP 5: Apply Schema to D1 ──────────────────────────────
Write-Step "Applying schema.sql to D1 database..."

$schemaResult = npx wrangler d1 execute $dbName --file=".\schema.sql" --account-id $env:CLOUDFLARE_ACCOUNT_ID 2>&1
$schemaStr = $schemaResult -join "`n"
Write-Host $schemaStr -ForegroundColor DarkGray

if ($schemaStr -match "error|Error|ERROR") {
    Write-Fail "Schema execution may have errors. Check output above."
    $continueAnyway = Read-Host "  Continue anyway? [y/N]"
    if ($continueAnyway -ne 'y' -and $continueAnyway -ne 'Y') { exit 1 }
} else {
    Write-Ok "Schema applied successfully."
}

# ── STEP 6: Deploy Worker ────────────────────────────────────
Write-Step "Deploying Cloudflare Worker 'haru-stream'..."

$deployResult = npx wrangler deploy --account-id $env:CLOUDFLARE_ACCOUNT_ID 2>&1
$deployStr = $deployResult -join "`n"
Write-Host $deployStr -ForegroundColor DarkGray

# Extract Worker URL
$workerUrlMatch = [regex]::Match($deployStr, 'https://haru-stream\.[a-z0-9\-]+\.workers\.dev')
if ($workerUrlMatch.Success) {
    $workerUrl = $workerUrlMatch.Value
    Write-Ok "Worker deployed: $workerUrl"
    $env:HS_WORKER_URL = $workerUrl
} else {
    Write-Info "Worker URL not auto-detected. Check output above."
    $workerUrl = Read-Host "  Paste your Worker URL (e.g. https://haru-stream.xxx.workers.dev)"
    $workerUrl = $workerUrl.Trim()
    $env:HS_WORKER_URL = $workerUrl
}

# ── STEP 7: Set JWT_SECRET on Worker ────────────────────────
Write-Step "Setting JWT_SECRET on Worker..."

# Use wrangler secret put via stdin
$env:HS_JWT_SECRET | npx wrangler secret put JWT_SECRET --account-id $env:CLOUDFLARE_ACCOUNT_ID 2>&1 | Out-Null
Write-Ok "JWT_SECRET set."

# ── STEP 8: Update Pages Proxy with Worker URL ──────────────
Write-Step "Updating Pages Functions proxy with Worker URL..."

$proxyPath = ".\functions\[[path]].js"
if (Test-Path $proxyPath) {
    $proxyContent = Get-Content $proxyPath -Raw
    $proxyContent = $proxyContent -replace "const WORKER_URL = '.*?';", "const WORKER_URL = '$workerUrl';"
    Set-Content $proxyPath $proxyContent -Encoding UTF8
    Write-Ok "Proxy updated: $proxyPath"
} else {
    Write-Info "Proxy file not found. Skipping."
}

# ── STEP 9: Commit & Push updated files ─────────────────────
Write-Step "Committing updated config files to GitHub..."

git add wrangler.toml "functions/[[path]].js" 2>&1 | Out-Null
$commitResult = git commit -m "deploy: update D1 database ID and worker URL for production" 2>&1
Write-Host ($commitResult -join "`n") -ForegroundColor DarkGray
git push origin main 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
Write-Ok "Changes pushed to GitHub."

# ── DONE ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   HaruStream PRO — DEPLOYMENT COMPLETE!              ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Worker URL   : $workerUrl" -ForegroundColor White
Write-Host "  Pages URL    : Connect GitHub repo to Cloudflare Pages" -ForegroundColor White
Write-Host "  DB ID        : $dbId" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Go to Cloudflare Dashboard (second account)" -ForegroundColor Yellow
Write-Host "  2. Workers & Pages -> Create -> Pages -> Connect to Git" -ForegroundColor Yellow
Write-Host "  3. Select repo: IlhamRomadon297/haru-stream" -ForegroundColor Yellow
Write-Host "  4. Build output directory: public" -ForegroundColor Yellow
Write-Host "  5. Leave build command EMPTY" -ForegroundColor Yellow
Write-Host "  6. Deploy! Pages will auto-redeploy on every git push." -ForegroundColor Yellow
Write-Host ""
Write-Host "  NOTE: Pages deployment must be done manually via Dashboard" -ForegroundColor DarkGray
Write-Host "  because it requires GitHub OAuth through the browser." -ForegroundColor DarkGray
Write-Host ""
