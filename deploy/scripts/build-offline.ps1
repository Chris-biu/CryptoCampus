[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$')]
    [string]$Version = 'dev',

    [Parameter()]
    [string]$EnvFile = '.env.example',

    [Parameter()]
    [string]$OutputDirectory = 'artifacts/offline'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = (Resolve-Path (Join-Path $scriptDirectory '../..')).Path
$resolvedEnvFile = if ([System.IO.Path]::IsPathRooted($EnvFile)) {
    (Resolve-Path $EnvFile).Path
} else {
    (Resolve-Path (Join-Path $repositoryRoot $EnvFile)).Path
}

$outputPath = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $repositoryRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$resolvedOutput = (Resolve-Path $outputPath).Path
$stageDirectory = Join-Path $resolvedOutput "cryptocampus-$Version"
$archivePath = "$stageDirectory.zip"

if ((Test-Path -LiteralPath $stageDirectory) -or (Test-Path -LiteralPath $archivePath)) {
    throw "Output already exists. Choose another version or archive it first: $stageDirectory"
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker with the Compose plugin is required.'
}

Push-Location $repositoryRoot
$previousVersion = [Environment]::GetEnvironmentVariable('CRYPTOCAMPUS_VERSION', 'Process')
try {
    [Environment]::SetEnvironmentVariable('CRYPTOCAMPUS_VERSION', $Version, 'Process')

    docker compose --env-file $resolvedEnvFile config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed.' }

    docker compose --env-file $resolvedEnvFile build
    if ($LASTEXITCODE -ne 0) { throw 'Compose image build failed.' }

    $images = @(docker compose --env-file $resolvedEnvFile config --images | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or $images.Count -eq 0) { throw 'Could not resolve the image list.' }

    New-Item -ItemType Directory -Path $stageDirectory | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageDirectory 'scripts') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageDirectory 'deploy/secrets') -Force | Out-Null

    Copy-Item -LiteralPath 'compose.yaml' -Destination $stageDirectory
    Copy-Item -LiteralPath '.env.example' -Destination (Join-Path $stageDirectory '.env.example')
    Copy-Item -LiteralPath 'deploy/README.md' -Destination (Join-Path $stageDirectory 'README.md')
    Copy-Item -LiteralPath 'deploy/scripts/start-offline.ps1' -Destination (Join-Path $stageDirectory 'scripts/start-offline.ps1')

    $generatedEnvironment = (Get-Content -Raw -Encoding UTF8 '.env.example') -replace '(?m)^CRYPTOCAMPUS_VERSION=.*$', "CRYPTOCAMPUS_VERSION=$Version"
    Set-Content -LiteralPath (Join-Path $stageDirectory '.env') -Value $generatedEnvironment -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $stageDirectory 'VERSION') -Value $Version -Encoding ascii

    $imageArchive = Join-Path $stageDirectory 'images.tar'
    docker image save --output $imageArchive @images
    if ($LASTEXITCODE -ne 0) { throw 'Image export failed.' }

    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $imageArchive).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $stageDirectory 'SHA256SUMS') -Value "$hash  images.tar" -Encoding ascii

    Compress-Archive -LiteralPath $stageDirectory -DestinationPath $archivePath -CompressionLevel Optimal
    Write-Host "Offline package created: $archivePath"
    Write-Host "After extraction run: powershell -ExecutionPolicy Bypass -File .\scripts\start-offline.ps1"
} finally {
    [Environment]::SetEnvironmentVariable('CRYPTOCAMPUS_VERSION', $previousVersion, 'Process')
    Pop-Location
}
