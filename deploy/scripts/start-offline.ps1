[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action = 'start'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot = (Resolve-Path (Join-Path $scriptDirectory '..')).Path
$environmentFile = Join-Path $packageRoot '.env'
$composeFile = Join-Path $packageRoot 'compose.yaml'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker with the Compose plugin is required.'
}
if (-not (Test-Path -LiteralPath $environmentFile)) {
    Copy-Item -LiteralPath (Join-Path $packageRoot '.env.example') -Destination $environmentFile
}

Push-Location $packageRoot
try {
    if ($Action -eq 'stop') {
        docker compose --env-file $environmentFile --file $composeFile down
        if ($LASTEXITCODE -ne 0) { throw 'Failed to stop the services.' }
        return
    }

    if ($Action -eq 'status') {
        docker compose --env-file $environmentFile --file $composeFile ps
        if ($LASTEXITCODE -ne 0) { throw 'Failed to read service status.' }
        return
    }

    $imageArchive = Join-Path $packageRoot 'images.tar'
    $checksumFile = Join-Path $packageRoot 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $imageArchive) -or -not (Test-Path -LiteralPath $checksumFile)) {
        throw 'The offline package is missing images.tar or SHA256SUMS.'
    }

    $expectedHash = ((Get-Content -LiteralPath $checksumFile -Raw).Trim() -split '\s+')[0]
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $imageArchive).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash.ToLowerInvariant()) {
        throw 'The SHA-256 checksum for images.tar is invalid.'
    }

    docker image load --input $imageArchive
    if ($LASTEXITCODE -ne 0) { throw 'Failed to load container images.' }

    docker compose --env-file $environmentFile --file $composeFile config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed.' }
    docker compose --env-file $environmentFile --file $composeFile up --detach --no-build --wait
    if ($LASTEXITCODE -ne 0) { throw 'Service startup or health checks failed.' }

    # Compose gives process environment variables precedence over values from
    # --env-file. Probe the same effective port so an operator override cannot
    # accidentally validate another service that happens to own port 8080.
    $configuredPort = [Environment]::GetEnvironmentVariable('CRYPTOCAMPUS_HTTP_PORT', 'Process')
    if (-not $configuredPort) {
        $configuredPort = (Get-Content -Encoding UTF8 -LiteralPath $environmentFile | Where-Object { $_ -match '^CRYPTOCAMPUS_HTTP_PORT=' } | Select-Object -First 1) -replace '^CRYPTOCAMPUS_HTTP_PORT=', ''
    }
    if (-not $configuredPort) { $configuredPort = '8080' }
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:$configuredPort/api/v1/system/status" -TimeoutSec 10
    Write-Host "CryptoCampus started: http://127.0.0.1:$configuredPort"
    Write-Host ("System status: api={0}, engine={1}, tlcp={2}" -f $status.api, $status.engine, $status.tlcp)
} finally {
    Pop-Location
}
