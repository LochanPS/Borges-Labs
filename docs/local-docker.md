# Local Docker — install once, keep it small

You only need this to run the **live** stack (`docker compose up` → Postgres 15 +
Redis 7 + authorize-svc). Tests are hermetic and need no Docker. Coding Task 1.4
needs no Docker.

## Why you (not Claude) have to install it

Docker Desktop needs **admin rights (UAC)** to enable the WSL2 feature and register
its service, and usually a **reboot**. Claude runs unelevated and can't do either.
Your machine already has **WSL2 + the hypervisor enabled**, so the install is clean.

## Install (the one manual step)

From an **elevated** PowerShell (Run as administrator):

```powershell
choco install docker-desktop -y
```

Or download Docker Desktop for Windows and run the installer. Then launch it once,
and in **Settings → General** confirm **"Use the WSL 2 based engine"** is on.

## Keep it from ballooning (do this right after install)

Docker's WSL2 backend keeps everything in one virtual disk that **grows but never
auto-shrinks** — the classic "Docker ate my C: drive". Two guards:

**1. Cap the disk image.** Docker Desktop → **Settings → Resources → Advanced →
"Disk image size"**. Set a hard ceiling (e.g. **32–48 GB**). Docker cannot exceed it.

**2. Cap RAM/CPU** so the WSL VM doesn't hog memory. Create `C:\Users\pokka\.wslconfig`:

```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
# Reclaim disk automatically when the guest frees it (needs a recent WSL):
[experimental]
autoMemoryReclaim=gradual
sparseVhd=true
```

`sparseVhd=true` makes new WSL disks shrink as data is freed — the single best
anti-balloon switch. Run `wsl --shutdown` after editing `.wslconfig`.

**3. Reclaim on demand.** Whenever you want space back:

```powershell
pwsh -File deploy/docker-reclaim.ps1
```

This prunes unused images/build cache and **compacts** the Docker vhdx so freed
bytes return to Windows. Add `-Hard` to also drop unused volumes (deletes stopped
projects' data — e.g. a Postgres volume you no longer need).

## Run the stack

```bash
cd deploy && docker compose up          # PG + Redis + authorize-svc
```

Then apply the key migration and mint a test key — see
[request-authentication.md](request-authentication.md).

## Don't want Docker at all?

The service only needs Postgres 15 + Redis 7. You can point `DATABASE_URL` /
`REDIS_URL` at any instances (a managed dev database, or **Memurai** as a native
Windows Redis) and run the service with `go run ./cmd/authorize-svc`. Docker is just
the one-command convenience.
