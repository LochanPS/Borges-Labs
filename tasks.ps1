# Windows task runner — mirrors the Makefile for hosts without `make`.
#   ./tasks.ps1 up | down | logs | run | build | test | tidy | fmt | vet
#              | gen-ts | test-contracts | test-python | test-ts | docs | test-all
param([Parameter(Position = 0)][string]$Task = "help")

$ErrorActionPreference = "Stop"
$SvcDir = "services/authorize-svc"
$Compose = @("docker", "compose", "-f", "deploy/docker-compose.yml")

function Invoke-Compose { param([string[]]$Args) & $Compose[0] $Compose[1..($Compose.Count-1)] @Args }

# Run a native command (python/npm/node) tolerating stderr output: many tools write
# warnings/notices to stderr on success, which $ErrorActionPreference='Stop' would
# otherwise turn into a spurious failure. Judge success by the exit code alone.
function Invoke-Native {
    param([scriptblock]$Script)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Script } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "command failed (exit $LASTEXITCODE)" }
}

$commit = (git rev-parse --short HEAD 2>$null); if (-not $commit) { $commit = "none" }
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-X main.version=dev -X main.commit=$commit -X main.date=$date"

switch ($Task) {
    "up"    { Invoke-Compose @("up", "-d", "--build") }
    "down"  { Invoke-Compose @("down") }
    "logs"  { Invoke-Compose @("logs", "-f") }
    "run"   { Push-Location $SvcDir; try { go run "-ldflags=$ldflags" ./cmd/authorize-svc } finally { Pop-Location } }
    "build" { Push-Location $SvcDir; try { go build "-ldflags=$ldflags" -o bin/authorize-svc.exe ./cmd/authorize-svc } finally { Pop-Location } }
    "test"  { Push-Location $SvcDir; try { go test ./... } finally { Pop-Location } }
    "tidy"  { Push-Location $SvcDir; try { go mod tidy } finally { Pop-Location } }
    "fmt"   { Push-Location $SvcDir; try { gofmt -w . } finally { Pop-Location } }
    "vet"   { Push-Location $SvcDir; try { go vet ./... } finally { Pop-Location } }
    "gen-ts" { Invoke-Native { node contracts/tools/gen-ts.mjs } }
    "test-contracts" {
        Invoke-Native { python contracts/tools/validate.py }
        Push-Location contracts/gen/go; try { Invoke-Native { go test ./... } } finally { Pop-Location }
    }
    "test-python" { Push-Location sdks/python; try { Invoke-Native { python -m pytest -q } } finally { Pop-Location } }
    "test-ts" {
        Push-Location sdks/ts
        try {
            Invoke-Native { npm install }
            Invoke-Native { npm run build }
            Invoke-Native { npm test }
        } finally { Pop-Location }
    }
    "docs" {
        Push-Location docs-site
        try { Invoke-Native { npm install }; Invoke-Native { npm run build } } finally { Pop-Location }
    }
    "dashboard" {
        Push-Location services/dashboard
        try { Invoke-Native { npm install }; Invoke-Native { npm run dev } } finally { Pop-Location }
    }
    "test-dashboard" {
        Push-Location services/dashboard
        try { Invoke-Native { npm install }; Invoke-Native { npm test }; Invoke-Native { npm run build } } finally { Pop-Location }
    }
    "test-all" {
        foreach ($t in @("test", "test-contracts", "test-python", "test-ts", "test-dashboard")) {
            Write-Host "== $t ==" -ForegroundColor Cyan
            & $PSCommandPath $t
            if (-not $?) { throw "task '$t' failed" }
        }
    }
    default {
        Write-Host "Tasks: up | down | logs | run | build | test | tidy | fmt | vet"
        Write-Host "       gen-ts | test-contracts | test-python | test-ts | docs"
        Write-Host "       dashboard | test-dashboard | test-all"
    }
}
