# Windows task runner — mirrors the Makefile for hosts without `make`.
#   ./tasks.ps1 up | down | logs | run | build | test | tidy | fmt | vet
param([Parameter(Position = 0)][string]$Task = "help")

$ErrorActionPreference = "Stop"
$SvcDir = "services/authorize-svc"
$Compose = @("docker", "compose", "-f", "deploy/docker-compose.yml")

function Invoke-Compose { param([string[]]$Args) & $Compose[0] $Compose[1..($Compose.Count-1)] @Args }

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
    default {
        Write-Host "Tasks: up | down | logs | run | build | test | tidy | fmt | vet"
    }
}
