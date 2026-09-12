import { afterEach, describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, unlink } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { ProxyConfig } from "../src/config"
import { isProxyEndpoint } from "../src/config"
import { manageClaudeSettings, recoverClaudeSettingsBackup } from "../src/claude-settings"

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe("Claude settings lifecycle", () => {
  test("writes proxy environment values and restores the exact original bytes", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const original = '{\n  "env": {\n    "ANTHROPIC_BASE_URL": "https://provider.example.test",\n    "KEEP": "yes"\n  },\n  "theme": "dark"\n}\n'
    await Bun.write(path, original)

    const config = settingsConfig(path)
    const session = await manageClaudeSettings(config)
    expect(session).toBeDefined()
    const managed = await Bun.file(path).json()
    expect(managed).toEqual({
      env: {
        ANTHROPIC_BASE_URL: "http://127.0.0.1:8787",
        KEEP: "yes",
        ANTHROPIC_API_KEY: "proxy-key",
      },
      theme: "dark",
    })

    await session?.restore()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("removes a settings file it created when none existed before startup", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const session = await manageClaudeSettings(settingsConfig(path))

    expect(await Bun.file(path).exists()).toBe(true)
    await session?.restore()
    expect(await Bun.file(path).exists()).toBe(false)
  })

  test("keeps settings changed by another process instead of overwriting them", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    await Bun.write(path, JSON.stringify({ env: { KEEP: "yes" } }))
    const session = await manageClaudeSettings(settingsConfig(path))

    await Bun.write(path, JSON.stringify({ env: { EXTERNAL: "change" } }))
    await session?.restore()
    expect(await Bun.file(path).json()).toEqual({ env: { EXTERNAL: "change" } })
  })

  test("restores the original bytes when only non-proxy settings changed", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const original = '{\n  "env": {\n    "KEEP": "yes"\n  },\n  "theme": "dark"\n}\n'
    await Bun.write(path, original)

    const session = await manageClaudeSettings(settingsConfig(path))
    const changed = await Bun.file(path).json()
    changed.theme = "light"
    await Bun.write(path, `${JSON.stringify(changed, null, 2)}\n`)

    await session?.restore()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
  })

  test("removes an inherited auth token instead of leaving two credential fields", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    await Bun.write(
      path,
      JSON.stringify({
        env: {
          ANTHROPIC_BASE_URL: "https://provider.example.test",
          ANTHROPIC_AUTH_TOKEN: "provider-token",
          ANTHROPIC_API_KEY: "stale-proxy-key",
        },
      }),
    )

    const session = await manageClaudeSettings(settingsConfig(path))
    const managed = await Bun.file(path).json()
    expect(managed.env).toEqual({
      ANTHROPIC_BASE_URL: "http://127.0.0.1:8787",
      ANTHROPIC_API_KEY: "proxy-key",
    })

    await session?.restore()
  })

  test("recovers a managed settings file left by an interrupted process", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const original = JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://provider.example.test" }, theme: "dark" })
    await Bun.write(path, original)

    const firstSession = await manageClaudeSettings(settingsConfig(path))
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(true)
    await unlink(`${path}.zero-domain.lock`)

    const secondSession = await manageClaudeSettings(settingsConfig(path))
    expect(await readFile(path, "utf8")).not.toBe(original)
    await secondSession?.restore()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    void firstSession
  })

  test("restoreSync also restores through the semantic ownership check", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const original = JSON.stringify({ env: { KEEP: "yes" }, theme: "dark" })
    await Bun.write(path, original)

    const session = await manageClaudeSettings(settingsConfig(path))
    const changed = await Bun.file(path).json()
    changed.theme = "light"
    await Bun.write(path, `${JSON.stringify(changed, null, 2)}\n`)

    session?.restoreSync()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
  })

  test("standalone recovery restores a stale backup without starting the proxy", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    const original = JSON.stringify({ env: { KEEP: "yes" }, theme: "dark" })
    await Bun.write(path, original)

    const session = await manageClaudeSettings(settingsConfig(path))
    await unlink(`${path}.zero-domain.lock`)
    const recoveryConfig = settingsConfig(path)
    recoveryConfig.claudeSettingsAuto = false

    expect(await recoverClaudeSettingsBackup(recoveryConfig)).toBe(true)
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    void session
  })

  test("clears a lock left by a process that is no longer running", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    await Bun.write(`${path}.zero-domain.lock`, JSON.stringify({ pid: 999_999_999 }))

    const session = await manageClaudeSettings(settingsConfig(path))
    expect(session).toBeDefined()
    await session?.restore()
  })

  test("captures the original CCSwitch provider before the settings file is redirected", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "settings.json")
    await Bun.write(
      path,
      JSON.stringify({
        env: {
          ANTHROPIC_BASE_URL: "https://provider.example.test/v1",
          ANTHROPIC_AUTH_TOKEN: "provider-token",
        },
      }),
    )
    const config = settingsConfig(path)
    config.upstreamSource = "ccswitch"
    config.ccswitchSettingsPath = path

    const session = await manageClaudeSettings(config)
    expect(config.upstreamURL).toBe("https://provider.example.test/v1")
    expect(config.upstreamAPIKey).toBe("provider-token")
    expect(config.upstreamAuthMode).toBe("bearer")
    await session?.restore()
  })

  test("recognizes loopback proxy URLs when listening on a wildcard host", () => {
    const config = settingsConfig("unused")
    config.listenHost = "0.0.0.0"
    expect(isProxyEndpoint("http://127.0.0.1:8787", config)).toBe(true)
    expect(isProxyEndpoint("http://localhost:8787", config)).toBe(true)
    expect(isProxyEndpoint("http://[::1]:8787", config)).toBe(true)
  })
})

async function temporaryDirectory() {
  const path = await mkdtemp(join(tmpdir(), "zero-domain-settings-test-"))
  directories.push(path)
  return path
}

function settingsConfig(path: string): ProxyConfig {
  return {
    listenHost: "127.0.0.1",
    listenPort: 8787,
    upstreamURL: "https://api.anthropic.com",
    upstreamAPIKey: "fallback-key",
    upstreamAuthMode: "anthropic",
    upstreamSource: "static",
    ccswitchSettingsPath: path,
    claudeSettingsAuto: true,
    claudeSettingsPath: path,
    claudeProxyURL: "http://127.0.0.1:8787",
    claudeProxyAPIKey: "proxy-key",
    codexSettingsAuto: false,
    codexConfigPath: "unused",
    codexProxyAPIKey: "proxy-key",
    codexUpstreamExplicit: false,
    proxyAPIKey: "proxy-key",
    proxyAuthPassthrough: false,
    adminToken: "admin-key",
    maxRequestBytes: 1_000_000,
    upstreamTimeoutMs: 10_000,
    reviewMode: "off",
    reviewScope: "all",
    judgeEnabled: false,
    judgeProvider: "anthropic",
    judgeBaseURL: "https://api.anthropic.com",
    judgeAPIKey: "judge-key",
    judgeModel: "claude-haiku",
    judgeTimeoutMs: 2_000,
    judgeMaxOutputTokens: 128,
    judgeMaxInputChars: 32_000,
    judgeMaxMessages: 12,
    judgeMaxConcurrent: 2,
    judgeMinIntervalMs: 0,
    judgeQueueSize: 32,
    judgeQueueBytes: 64_000_000,
    judgeMaxRetries: 0,
    judgeRetryBaseMs: 1,
    judgeFailOpen: false,
    disconnectOnBlock: false,
    auditPath: "unused",
    auditIncludeBody: "off",
    auditStdout: "off",
  }
}
