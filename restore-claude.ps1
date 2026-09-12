param(
    [string]$SettingsFile,
    [string]$BackupFile
)

if (Test-Path $BackupFile) {
    Write-Host "  正在还原原始 settings.json..."
    Copy-Item -Path $BackupFile -Destination $SettingsFile -Force
    Remove-Item -Path $BackupFile -Force
    Write-Host "  Claude settings 已还原"
} else {
    Write-Host "  未找到备份，跳过还原"
}