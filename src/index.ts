import { clientSettingsPaths, loadConfig } from "./config"
import { DEFAULT_ADMIN_CONFIG_PATH, readConfigOverrides } from "./config-store"
import { manageClaudeSettings, recoverClaudeSettingsBackup, type ClaudeSettingsSession } from "./claude-settings"
import { manageCodexSettings, recoverCodexSettingsBackup, type CodexSettingsSession } from "./codex-settings"
import { createProxy } from "./proxy"

type SettingsSession = ClaudeSettingsSession | CodexSettingsSession

const adminConfigPath = Bun.env.ADMIN_CONFIG_PATH ?? DEFAULT_ADMIN_CONFIG_PATH
const persistedOverrides = await readConfigOverrides(adminConfigPath)
const effectiveEnv = { ...Bun.env, ...persistedOverrides, ADMIN_CONFIG_PATH: adminConfigPath }
const settingsPaths = clientSettingsPaths(effectiveEnv)
await recoverClaudeSettingsBackup(settingsPaths)
await recoverCodexSettingsBackup(settingsPaths)
const config = loadConfig(effectiveEnv)

// 审计日志不做启动清理：audit.ts 已实现 100MB 自动轮转，
// 历史记录默认保留，避免安全审计轨迹在重启时静默丢失。
// 如需手工清理，请通过管理后台删除或手动归档 ./data/ 下的文件。

const handler = createProxy(config)
const server = Bun.serve({
  hostname: config.listenHost,
  port: config.listenPort,
  fetch: handler,
  // 审查与上游均可能是长请求，给两段超时留出缓冲。
  idleTimeout: 160,
})
if (server.port === undefined) {
  server.stop()
  throw new Error("zero-domain did not bind a port")
}
config.listenPort = server.port

if (config.claudeSettingsAuto && config.claudeProxyURL === undefined) {
  config.claudeProxyURL = `http://127.0.0.1:${server.port}`
}
if (config.codexSettingsAuto && config.codexProxyURL === undefined) {
  config.codexProxyURL = `http://127.0.0.1:${server.port}/codex`
}

const settingsSessions: SettingsSession[] = []
let stopping = false

async function restoreSettings() {
  let firstError: unknown
  for (const session of [...settingsSessions].reverse()) {
    try {
      await session.restore()
    } catch (error) {
      firstError ??= error
    }
  }
  if (firstError) throw firstError
}

function restoreSettingsSync() {
  for (const session of [...settingsSessions].reverse()) {
    try {
      session.restoreSync()
    } catch (error) {
      console.error(`[zero-domain] settings restore failed: ${formatError(error)}`)
    }
  }
}

const stop = async (code = 0) => {
  if (stopping) return
  stopping = true
  server.stop()
  try {
    await restoreSettings()
  } catch (error) {
    console.error(`[zero-domain] settings restore failed: ${formatError(error)}`)
    code = 1
  }
  process.exit(code)
}

for (const signal of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
  process.once(signal, () => void stop())
}
process.once("uncaughtException", (error) => {
  console.error(`[zero-domain] uncaught exception: ${error.stack ?? error.message}`)
  void stop(1)
})
process.once("unhandledRejection", (reason) => {
  console.error(`[zero-domain] unhandled rejection: ${formatError(reason)}`)
  void stop(1)
})
process.once("exit", restoreSettingsSync)

try {
  const claudeSession = await manageClaudeSettings(config)
  if (claudeSession) settingsSessions.push(claudeSession)
  const codexSession = await manageCodexSettings(config)
  if (codexSession) settingsSessions.push(codexSession)
} catch (error) {
  server.stop()
  try {
    await restoreSettings()
  } catch (restoreError) {
    console.error(`[zero-domain] settings rollback failed: ${formatError(restoreError)}`)
  }
  throw error
}

console.log(`[zero-domain] 监听地址: http://${server.hostname}:${server.port}`)
console.log(
  `[zero-domain] Claude 上游: ${
    config.upstreamSource === "ccswitch"
      ? `ccswitch/${config.ccswitchSettingsPath}`
      : config.upstreamURL
  }`,
)
console.log(`[zero-domain] Codex 上游: ${config.codexUpstreamURL ?? "https://api.openai.com/v1"}`)
console.log(
  `[zero-domain] 审查: ${config.reviewMode === "llm" ? `${config.judgeProvider}/${config.judgeModel}` : "关闭"}`,
)
console.log(
  `[zero-domain] 审查范围: ${config.reviewScope}; 并发 ${config.judgeMaxConcurrent}; 队列 ${config.judgeQueueSize}/${config.judgeQueueBytes} bytes; 重试 ${config.judgeMaxRetries}`,
)
if (config.reviewMode === "llm" && config.judgeFailOpen) {
  console.warn(
    "[zero-domain] 警告: REVIEW_FAIL_OPEN=true，审查故障/无法识别时会放行请求；生产环境强烈建议 false（默认）",
  )
}
console.log(`[zero-domain] 审计文件: ${config.auditPath}`)
console.log(`[zero-domain] 审计输出: ${config.auditStdout}`)
if (config.claudeSettingsAuto) {
  console.log(`[zero-domain] Claude 设置: ${config.claudeSettingsPath} -> ${config.claudeProxyURL}`)
}
if (config.codexSettingsAuto) {
  console.log(`[zero-domain] Codex 设置: ${config.codexConfigPath} -> ${config.codexProxyURL}`)
}

function formatError(error: unknown) {
  return error instanceof Error ? error.stack ?? error.message : String(error)
}
