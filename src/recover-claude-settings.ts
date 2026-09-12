import { clientSettingsPaths } from "./config"
import { DEFAULT_ADMIN_CONFIG_PATH, readConfigOverrides } from "./config-store"
import { recoverClaudeSettingsBackup } from "./claude-settings"
import { recoverCodexSettingsBackup } from "./codex-settings"

const adminConfigPath = Bun.env.ADMIN_CONFIG_PATH ?? DEFAULT_ADMIN_CONFIG_PATH
const persistedOverrides = await readConfigOverrides(adminConfigPath)
const settingsPaths = clientSettingsPaths({ ...Bun.env, ...persistedOverrides, ADMIN_CONFIG_PATH: adminConfigPath })

const claudeRecovered = await attemptRecovery("Claude/CCSwitch", () => recoverClaudeSettingsBackup(settingsPaths))
const codexRecovered = await attemptRecovery("Codex", () => recoverCodexSettingsBackup(settingsPaths))
if (claudeRecovered) console.log("[zero-domain] 已回收遗留的 Claude/CCSwitch 设置备份")
if (codexRecovered) console.log("[zero-domain] 已回收遗留的 Codex 设置备份")

async function attemptRecovery(name: string, recover: () => Promise<boolean>) {
  try {
    return await recover()
  } catch (error) {
    console.error(
      `[zero-domain] ${name} 设置备份回收失败: ${error instanceof Error ? error.message : String(error)}`,
    )
    process.exitCode = 1
    return false
  }
}
