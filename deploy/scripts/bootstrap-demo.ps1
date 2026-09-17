param(
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$resolvedEnv = Join-Path $repoRoot $EnvFile
$secretsPath = Join-Path $repoRoot "deploy\secrets"

if (-not (Test-Path -LiteralPath $resolvedEnv -PathType Leaf)) {
    throw "未找到 $resolvedEnv；请先从 .env.example 创建本机 .env 并填写演示口令。"
}

$settings = @{}
foreach ($line in Get-Content -LiteralPath $resolvedEnv) {
    if ($line -match '^\s*([^#=]+)=(.*)$') {
        $settings[$matches[1].Trim()] = $matches[2].Trim()
    }
}

if ($settings['CRYPTOCAMPUS_ENV'] -in @('prod', 'production')) {
    throw "生产环境禁止初始化演示身份与密钥。"
}

$required = @(
    'CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD',
    'CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD',
    'CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD',
    'CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD'
)
foreach ($name in $required) {
    if (-not $settings[$name]) { throw "本机 .env 缺少 $name。" }
}

New-Item -ItemType Directory -Force -Path $secretsPath | Out-Null
Push-Location $repoRoot
try {
    docker compose --env-file $resolvedEnv build server
    if ($LASTEXITCODE -ne 0) { throw "Server 镜像构建失败。" }

    $arguments = @(
        'run', '--rm', '--no-deps',
        '--entrypoint', 'python',
        '-e', 'CRYPTOCAMPUS_ENV=development',
        '-e', 'CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP=1',
        '-e', "CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD=$($settings['CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD'])",
        '-e', "CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD=$($settings['CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD'])",
        '-e', "CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD=$($settings['CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD'])",
        '-e', "CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD=$($settings['CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD'])",
        '-v', "${secretsPath}:/run/secrets/cryptocampus",
        'server', '-m', 'app.db.bootstrap_demo'
    )
    & docker compose --env-file $resolvedEnv @arguments
    if ($LASTEXITCODE -ne 0) { throw "演示环境初始化失败。" }
}
finally {
    Pop-Location
}

Write-Host "演示 CA、证书、账号与业务密钥已写入 Git 忽略目录 deploy/secrets。"
