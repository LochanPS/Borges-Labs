# docker-reclaim.ps1 — reclaim Docker/WSL disk space.
#
# Docker Desktop on the WSL2 backend stores everything in a virtual disk
# (docker_data ext4.vhdx) that GROWS as you build/pull but NEVER shrinks on its
# own. This is the usual "Docker ballooned my C: drive" cause. Run this whenever
# you want space back — safe: it removes only dangling/unused data, then compacts
# the vhdx so freed space returns to Windows.
#
#   pwsh -File deploy/docker-reclaim.ps1            # prune unused + compact
#   pwsh -File deploy/docker-reclaim.ps1 -Hard      # also drop unused VOLUMES (data!)
#
# -Hard deletes unused named volumes (e.g. a stopped project's Postgres data).
# Only use it when you don't need any stopped container's data.

param([switch]$Hard)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "docker not found — nothing to reclaim." ; exit 0
}

Write-Host "== docker usage before =="
docker system df

Write-Host "`n== pruning unused images / build cache / stopped containers / networks =="
if ($Hard) {
    docker system prune -af --volumes
} else {
    docker system prune -af   # -a: unused images too; keeps named volumes
    docker builder prune -af
}

Write-Host "`n== docker usage after prune =="
docker system df

# Compact the WSL2 virtual disk so freed bytes return to Windows.
Write-Host "`n== compacting the Docker WSL disk =="
$vhdx = @(
    "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx",
    "$env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $vhdx) {
    Write-Host "Could not locate the Docker WSL vhdx; skipping compaction."
    Write-Host "(Docker Desktop > Settings > Resources also has a disk-image size limit.)"
    exit 0
}

Write-Host "vhdx: $vhdx"
$before = (Get-Item $vhdx).Length
wsl --shutdown
Start-Sleep -Seconds 3

# diskpart compact needs no admin for a file you own; Optimize-VHD would need Hyper-V.
$tmp = New-TemporaryFile
@(
    "select vdisk file=`"$vhdx`"",
    "attach vdisk readonly",
    "compact vdisk",
    "detach vdisk"
) | Set-Content -Encoding ASCII $tmp
diskpart /s $tmp
Remove-Item $tmp -ErrorAction SilentlyContinue

$after = (Get-Item $vhdx).Length
$savedMB = [math]::Round(($before - $after) / 1MB, 1)
Write-Host ("`nreclaimed {0} MB (vhdx {1} -> {2} MB)" -f $savedMB, [math]::Round($before/1MB,1), [math]::Round($after/1MB,1))
