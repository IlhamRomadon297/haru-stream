param()
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$m) Write-Host ""; Write-Host ">>> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Fail { param([string]$m) Write-Host "  [!!] $m" -ForegroundColor Red }
function Write-Info { param([string]$m) Write-Host "  [-]  $m" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "  =================================================" -ForegroundColor Magenta
Write-Host "    HaruStream PRO - Automated Deploy Script       " -ForegroundColor Magenta
Write-Host "    Target: Cloudflare Second Account              " -ForegroundColor Magenta
Write-Host "  =================================================" -ForegroundColor Magenta
Write-Host ""

# ── STEP 0: Node.js check ───────────────────────────────────
Write-Step "Step 0: Checking Node.js..."
try {
    $nodeVer = & node --version 2>&1
    Write-Ok "Node.js found: $nodeVer"
} catch {
    Write-Fail "Node.js not found. Install from https://nodejs.org"
    exit 1
}

# ── STEP 1: Wrangler install ─────────────────────────────────
Write-Step "Step 1: Wrangler setup..."
$wranglerCmd = Join-Path (Join-Path (Join-Path $PSScriptRoot "node_modules") ".bin") "wrangler.cmd"
if (-not (Test-Path $wranglerCmd)) {
    Write-Info "Running npm install..."
    & npm install --silent
    Write-Ok "Wrangler installed."
} else {
    Write-Ok "Wrangler already installed."
}

# ── STEP 2: Credentials ──────────────────────────────────────
Write-Step "Step 2: Loading credentials..."

$envFile = Join-Path $PSScriptRoot ".env.deploy"
if (Test-Path $envFile) {
    Write-Info "Found .env.deploy, loading..."
    $envLines = Get-Content $envFile
    foreach ($line in $envLines) {
        $idx = $line.IndexOf('=')
        if ($idx -gt 0) {
            $k = $line.Substring(0, $idx).Trim()
            $v = $line.Substring($idx + 1).Trim()
            [System.Environment]::SetEnvironmentVariable($k, $v, 'Process')
        }
    }
}

if ([string]::IsNullOrEmpty($env:CLOUDFLARE_API_TOKEN)) {
    Write-Info "Get your API Token from: https://dash.cloudflare.com/profile/api-tokens"
    Write-Info "Template: Edit Cloudflare Workers"
    $t = Read-Host "  Enter CF API Token (second account)"
    $env:CLOUDFLARE_API_TOKEN = $t.Trim()
}

if ([string]::IsNullOrEmpty($env:CLOUDFLARE_ACCOUNT_ID)) {
    Write-Info "Account ID is shown in the right sidebar of your CF dashboard"
    $a = Read-Host "  Enter CF Account ID (second account)"
    $env:CLOUDFLARE_ACCOUNT_ID = $a.Trim()
}

if ([string]::IsNullOrEmpty($env:HS_JWT_SECRET)) {
    $j = Read-Host "  Enter JWT_SECRET (any long random string, min 32 chars)"
    $env:HS_JWT_SECRET = $j.Trim()
}

$saveAns = Read-Host "  Save credentials to .env.deploy for next time? [y/N]"
if ($saveAns -eq 'y' -or $saveAns -eq 'Y') {
    $lines = @(
        "CLOUDFLARE_API_TOKEN=$($env:CLOUDFLARE_API_TOKEN)",
        "CLOUDFLARE_ACCOUNT_ID=$($env:CLOUDFLARE_ACCOUNT_ID)",
        "HS_JWT_SECRET=$($env:HS_JWT_SECRET)"
    )
    Set-Content -Path $envFile -Value $lines -Encoding UTF8
    Write-Ok "Credentials saved to .env.deploy"

    $giPath = Join-Path $PSScriptRoot ".gitignore"
    if (Test-Path $giPath) {
        $giContent = Get-Content $giPath -Raw
        if ($giContent -notmatch 'env\.deploy') {
            Add-Content $giPath ".env.deploy"
            Write-Ok ".env.deploy added to .gitignore"
        }
    }
}

$shortToken = $env:CLOUDFLARE_API_TOKEN.Substring(0, [Math]::Min(8, $env:CLOUDFLARE_API_TOKEN.Length))
Write-Ok "Account ID : $($env:CLOUDFLARE_ACCOUNT_ID)"
Write-Ok "Token      : $shortToken..."

# ── STEP 3: Create D1 Database ───────────────────────────────
Write-Step "Step 3: Creating D1 database 'haru-stream-db'..."

$dbName = "haru-stream-db"
$dbOut  = & npx wrangler d1 create $dbName 2>&1
$dbStr  = ($dbOut -join "`n")
Write-Host $dbStr -ForegroundColor DarkGray

$dbId = $null
foreach ($ln in $dbOut) {
    if ($ln -match 'database_id\s*=\s*"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"') {
        $dbId = $Matches[1]
        break
    }
}

if ([string]::IsNullOrEmpty($dbId)) {
    Write-Info "DB ID not found in create output. Checking list..."
    $listOut = & npx wrangler d1 list 2>&1
    Write-Host ($listOut -join "`n") -ForegroundColor DarkGray
    foreach ($ln in $listOut) {
        if ($ln -match $dbName) {
            if ($ln -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                $dbId = $Matches[1]
                break
            }
        }
    }
}

if ([string]::IsNullOrEmpty($dbId)) {
    Write-Fail "Cannot auto-detect Database ID."
    $manId = Read-Host "  Paste D1 Database ID manually"
    $dbId  = $manId.Trim()
}

Write-Ok "D1 Database ID: $dbId"

# ── STEP 4: Update wrangler.toml ────────────────────────────
Write-Step "Step 4: Updating wrangler.toml..."

$tomlPath = Join-Path $PSScriptRoot "wrangler.toml"
$toml     = Get-Content $tomlPath -Raw
$toml     = $toml.Replace('database_id = "REPLACE_WITH_YOUR_D1_DATABASE_ID"',    "database_id = `"$dbId`"")
$toml     = $toml.Replace('database_id = "REPLACE_WITH_YOUR_D1_DEV_DATABASE_ID"', "database_id = `"$dbId`"")
Set-Content -Path $tomlPath -Value $toml -Encoding UTF8
Write-Ok "wrangler.toml updated with database_id."

# ── STEP 5: Apply schema.sql ─────────────────────────────────
Write-Step "Step 5: Applying schema.sql to D1..."

$schemaPath = Join-Path $PSScriptRoot "schema.sql"
$schemaOut  = & npx wrangler d1 execute $dbName --file $schemaPath 2>&1
$schemaStr  = ($schemaOut -join "`n")
Write-Host $schemaStr -ForegroundColor DarkGray

if ($schemaStr -match '(?i)\berror\b') {
    Write-Fail "Schema may have issues. Review output above."
    $cont = Read-Host "  Continue anyway? [y/N]"
    if ($cont -ne 'y' -and $cont -ne 'Y') { exit 1 }
} else {
    Write-Ok "Schema applied."
}

# ── STEP 6: Deploy Worker ────────────────────────────────────
Write-Step "Step 6: Deploying Worker..."

$depOut = & npx wrangler deploy 2>&1
$depStr = ($depOut -join "`n")
Write-Host $depStr -ForegroundColor DarkGray

$workerUrl = $null
foreach ($ln in $depOut) {
    if ($ln -match '(https://haru-stream\.[a-z0-9-]+\.workers\.dev)') {
        $workerUrl = $Matches[1]
        break
    }
}

if ([string]::IsNullOrEmpty($workerUrl)) {
    Write-Info "Worker URL not auto-detected."
    $manUrl    = Read-Host "  Paste Worker URL (e.g. https://haru-stream.xxx.workers.dev)"
    $workerUrl = $manUrl.Trim()
}

Write-Ok "Worker deployed: $workerUrl"

# ── STEP 7: Set JWT_SECRET ───────────────────────────────────
Write-Step "Step 7: Setting JWT_SECRET on Worker..."
$env:HS_JWT_SECRET | & npx wrangler secret put JWT_SECRET 2>&1 | Out-Null
Write-Ok "JWT_SECRET set."

# ── STEP 8: Update Pages proxy ───────────────────────────────
Write-Step "Step 8: Updating Pages proxy..."

$proxyPath = Join-Path (Join-Path $PSScriptRoot "functions") "[[path]].js"
if (Test-Path $proxyPath) {
    $px = Get-Content $proxyPath -Raw
    $px = $px.Replace("const WORKER_URL = 'https://haru-stream.YOUR_SUBDOMAIN.workers.dev';", "const WORKER_URL = '$workerUrl';")
    $px = [regex]::Replace($px, "const WORKER_URL = 'https://[^']+\.workers\.dev';", "const WORKER_URL = '$workerUrl';")
    Set-Content -Path $proxyPath -Value $px -Encoding UTF8
    Write-Ok "Proxy updated: $workerUrl"
} else {
    Write-Info "Proxy file not found, skipping."
}

# ── STEP 9: Git push ─────────────────────────────────────────
Write-Step "Step 9: Pushing to GitHub..."

& git add "wrangler.toml" 2>&1 | Out-Null
& git add "functions/[[path]].js" 2>&1 | Out-Null
$commitOut = & git commit -m "deploy: production D1 ID and Worker URL" 2>&1
Write-Info ($commitOut -join " ")
$pushOut = & git push origin main 2>&1
Write-Info ($pushOut -join " ")
Write-Ok "Pushed to GitHub."

# ── DONE ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "  =================================================" -ForegroundColor Green
Write-Host "    DEPLOYMENT COMPLETE!                           " -ForegroundColor Green
Write-Host "  =================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Worker : $workerUrl" -ForegroundColor White
Write-Host "  DB ID  : $dbId" -ForegroundColor White
Write-Host ""
Write-Host "  LAST STEP - Connect Pages (one-time, via browser):" -ForegroundColor Yellow
Write-Host "  1. Login second CF account at dash.cloudflare.com" -ForegroundColor Yellow
Write-Host "  2. Workers and Pages > Create > Pages > Connect to Git" -ForegroundColor Yellow
Write-Host "  3. Select repo: IlhamRomadon297/haru-stream" -ForegroundColor Yellow
Write-Host "  4. Build output directory: public" -ForegroundColor Yellow
Write-Host "  5. Build command: leave EMPTY" -ForegroundColor Yellow
Write-Host "  6. Click Save and Deploy" -ForegroundColor Yellow
Write-Host ""
