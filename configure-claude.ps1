param(
    [string]$SettingsFile,
    [string]$BackupFile,
    [string]$ProxyURL = "http://127.0.0.1:8787"
)

function Normalize-BaseUrl([string]$value) {
    if (-not $value) { return "" }
    return $value.Trim().TrimEnd('/')
}

# Backup then write proxy Base URL
if (Test-Path $SettingsFile) {
    $json = Get-Content $SettingsFile -Raw | ConvertFrom-Json
    $currentBase = Normalize-BaseUrl ([string]$json.env.ANTHROPIC_BASE_URL)
    $proxyBase = Normalize-BaseUrl $ProxyURL
    $alreadyProxied = $currentBase -eq $proxyBase

    if ($alreadyProxied) {
        Write-Host "  ANTHROPIC_BASE_URL 已指向代理，保留现有备份不动"
    } else {
        Write-Host "  正在备份 settings.json..."
        Copy-Item -Path $SettingsFile -Destination $BackupFile -Force
        Write-Host "  正在设置 ANTHROPIC_BASE_URL 为 $ProxyURL..."
        $json.env.ANTHROPIC_BASE_URL = $ProxyURL
        $json | ConvertTo-Json -Depth 100 | Set-Content $SettingsFile -Encoding UTF8
        Write-Host "  Claude settings 已配置完成"
    }
} else {
    Write-Host "  警告: 未找到 settings.json：$SettingsFile"
}