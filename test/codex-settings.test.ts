import { afterEach, describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, unlink } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { parse, stringify } from "smol-toml"
import type { ProxyConfig } from "../src/config"
import { manageCodexSettings, recoverCodexSettingsBackup } from "../src/codex-settings"

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe("Codex settings lifecycle", () => {
  test("restores the precise original TOML bytes", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = 'model = "gpt-5"\r\n# formatting and comments must survive\r\napproval_policy = "on-request"\r\n'
    await Bun.write(path, original)

    const session = await manageCodexSettings(settingsConfig(path))
    expect(session).toBeDefined()
    expect(await readFile(path, "utf8")).not.toBe(original)

    await session?.restore()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("removes a config file that did not exist before management", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, ".codex", "config.toml")

    const session = await manageCodexSettings(settingsConfig(path))
    expect(await Bun.file(path).exists()).toBe(true)

    await session?.restore()
    expect(await Bun.file(path).exists()).toBe(false)
  })

  test("clones the active custom provider, captures its upstream, and adds proxy authentication", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(
      path,
      [
        'model_provider = "company"',
        'model = "company-model"',
        "",
        "[model_providers.company]",
        'name = "Company gateway"',
        'base_url = "https://provider.example.test/v1/"',
        'env_key = "COMPANY_API_KEY"',
        'wire_api = "responses"',
        "",
        "[model_providers.company.http_headers]",
        'x-tenant = "tenant-a"',
        "",
      ].join("\n"),
    )
    const config = settingsConfig(path)

    const session = await manageCodexSettings(config)
    const managed = await parsedConfig(path)
    const providerID = managed.model_provider as string
    const providers = managed.model_providers as Record<string, Record<string, unknown>>
    const provider = providers[providerID]

    expect(providerID).not.toBe("company")
    expect(providers.company.base_url).toBe("https://provider.example.test/v1/")
    expect(provider.name).toBe("Company gateway")
    expect(provider.env_key).toBe("COMPANY_API_KEY")
    expect(provider.base_url).toBe("http://127.0.0.1:8787/codex")
    expect(provider.wire_api).toBe("responses")
    expect(provider.http_headers).toEqual({
      "x-tenant": "tenant-a",
      "x-zero-domain-key": "codex-proxy-key",
    })
    expect(config.codexUpstreamURL).toBe("https://provider.example.test/v1")
    await session?.restore()
  })

  test("creates an authenticated Responses provider for built-in OpenAI", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(path, 'model = "gpt-5"\n')

    const session = await manageCodexSettings(settingsConfig(path))
    const managed = await parsedConfig(path)
    const providerID = managed.model_provider as string
    const providers = managed.model_providers as Record<string, Record<string, unknown>>

    expect(providerID).toBe("zero-domain")
    expect(providers[providerID]).toEqual({
      name: "OpenAI through zero-domain",
      base_url: "http://127.0.0.1:8787/codex",
      wire_api: "responses",
      requires_openai_auth: true,
      http_headers: { "x-zero-domain-key": "codex-proxy-key" },
    })
    await session?.restore()
  })

  test("selects the ChatGPT Codex upstream for built-in ChatGPT authentication", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(path, 'model = "gpt-5"\n')
    await Bun.write(join(directory, "auth.json"), `${JSON.stringify({ auth_mode: "chatgpt" })}\n`)
    const config = settingsConfig(path)
    config.codexUpstreamURL = undefined

    const session = await manageCodexSettings(config)

    expect(config).toMatchObject({ codexUpstreamURL: "https://chatgpt.com/backend-api/codex" })
    await session?.restore()
  })

  test("chooses a unique managed provider id without replacing a collision", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(
      path,
      [
        'model_provider = "openai"',
        "",
        "[model_providers.zero-domain]",
        'name = "User provider"',
        'base_url = "https://existing.example.test/v1"',
        'wire_api = "responses"',
        "",
      ].join("\n"),
    )

    const session = await manageCodexSettings(settingsConfig(path))
    const managed = await parsedConfig(path)
    const providers = managed.model_providers as Record<string, Record<string, unknown>>

    expect(managed.model_provider).toBe("zero-domain-2")
    expect(providers["zero-domain"].name).toBe("User provider")
    expect(providers["zero-domain-2"].base_url).toBe("http://127.0.0.1:8787/codex")
    await session?.restore()
  })

  test("semantically recovers an interrupted session even when auto-management is now disabled", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = 'model = "gpt-5"\n'
    await Bun.write(path, original)

    const config = settingsConfig(path)
    const interruptedSession = await manageCodexSettings(config)
    await unlink(`${path}.zero-domain.lock`)

    const reformatted = await parsedConfig(path)
    reformatted.approval_policy = "never"
    await Bun.write(path, `${stringify(reformatted)}\n`)
    config.codexSettingsAuto = false

    expect(await recoverCodexSettingsBackup(config)).toBe(true)
    const recovered = await parsedConfig(path)
    expect(recovered.model).toBe("gpt-5")
    expect(recovered.approval_policy).toBe("never")
    expect(recovered.model_provider).toBeUndefined()
    expect(recovered.model_providers).toBeUndefined()
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await manageCodexSettings(config)).toBeUndefined()
    void interruptedSession
  })

  test("removes the managed provider while preserving external non-managed fields", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(
      path,
      [
        'model_provider = "company"',
        'model = "company-model"',
        "",
        "[model_providers.company]",
        'base_url = "https://provider.example.test/v1"',
        'wire_api = "responses"',
        "",
      ].join("\n"),
    )

    const session = await manageCodexSettings(settingsConfig(path))
    const changed = await parsedConfig(path)
    const managedProviderID = changed.model_provider as string
    changed.sandbox_mode = "workspace-write"
    await Bun.write(path, `${stringify(changed)}\n`)

    await session?.restore()
    const restored = await parsedConfig(path)
    const providers = restored.model_providers as Record<string, Record<string, unknown>>
    expect(restored.model_provider).toBe("company")
    expect(restored.sandbox_mode).toBe("workspace-write")
    expect(providers.company.base_url).toBe("https://provider.example.test/v1")
    expect(providers[managedProviderID]).toBeUndefined()
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
  })

  test("preserves an external provider switch while removing the injected provider", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(
      path,
      [
        'model_provider = "company"',
        "",
        "[model_providers.company]",
        'base_url = "https://company.example.test/v1"',
        'wire_api = "responses"',
        "",
        "[model_providers.alternate]",
        'base_url = "https://alternate.example.test/v1"',
        'wire_api = "responses"',
        "",
      ].join("\n"),
    )
    const session = await manageCodexSettings(settingsConfig(path))
    const changed = await parsedConfig(path)
    const managedProvider = changed.model_provider as string
    changed.model_provider = "alternate"
    await Bun.write(path, `${stringify(changed)}\n`)

    await session?.restore()

    const restored = await parsedConfig(path)
    const providers = restored.model_providers as Record<string, unknown>
    expect(restored.model_provider).toBe("alternate")
    expect(providers[managedProvider]).toBeUndefined()
    expect(providers.company).toBeDefined()
    expect(providers.alternate).toBeDefined()
    expect(await Bun.file(`${path}.zero-domain.conflict-original`).exists()).toBe(false)
  })

  test("reports invalid TOML without changing the original", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = 'model_provider = "unfinished\n'
    await Bun.write(path, original)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(/valid TOML.*config\.toml/i)
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("does not take over a lock owned by a live process", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const lockPath = `${path}.zero-domain.lock`
    await Bun.write(path, 'model = "gpt-5"\n')
    await Bun.write(lockPath, `${JSON.stringify({ pid: process.pid })}\n`)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(/already managed/i)
    expect(await Bun.file(lockPath).exists()).toBe(true)
  })

  test("clears a lock whose owner process no longer exists", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(`${path}.zero-domain.lock`, `${JSON.stringify({ pid: 999_999_999 })}\n`)

    const session = await manageCodexSettings(settingsConfig(path))
    expect(session).toBeDefined()
    await session?.restore()
  })

  test("restoreSync restores the exact original and clears lifecycle files", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = '# exact\nmodel = "gpt-5"\n'
    await Bun.write(path, original)

    const session = await manageCodexSettings(settingsConfig(path))
    session?.restoreSync()

    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("preserves an externally modified config and writes an exact original recovery artifact", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const conflictPath = `${path}.zero-domain.conflict-original`
    const original = '# original bytes\nmodel = "gpt-5"\n'
    const external = '# external owner\nmodel = "different"\n'
    await Bun.write(path, original)

    const session = await manageCodexSettings(settingsConfig(path))
    await Bun.write(path, external)
    await session?.restore()

    expect(await readFile(path, "utf8")).toBe(external)
    expect(await readFile(conflictPath, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("rejects a captured custom upstream that points back to the proxy", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = [
      'model_provider = "loop"',
      "",
      "[model_providers.loop]",
      'base_url = "http://localhost:8787/codex"',
      'wire_api = "responses"',
      "",
    ].join("\n")
    await Bun.write(path, original)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(/forwarding loop/i)
    expect(await readFile(path, "utf8")).toBe(original)
  })

  test("rejects an explicit upstream that points back to the proxy", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    await Bun.write(path, 'model = "gpt-5"\n')
    const config = settingsConfig(path)
    config.codexUpstreamURL = "http://127.0.0.1:8787/codex"
    config.codexUpstreamExplicit = true

    await expect(manageCodexSettings(config)).rejects.toThrow(/must not point back/i)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("requires an upstream base_url for a custom provider unless one was explicitly configured", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = [
      'model_provider = "company"',
      "",
      "[model_providers.company]",
      'name = "Company gateway"',
      'wire_api = "responses"',
      "",
    ].join("\n")
    await Bun.write(path, original)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(/must define base_url.*CODEX_UPSTREAM_URL/i)
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("rejects a custom provider that is not Responses-compatible", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const original = [
      'model_provider = "legacy"',
      "",
      "[model_providers.legacy]",
      'base_url = "https://legacy.example.test/v1"',
      'wire_api = "chat"',
      "",
    ].join("\n")
    await Bun.write(path, original)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(/wire_api = "responses"/i)
    expect(await readFile(path, "utf8")).toBe(original)
  })

  test("rejects a sibling profile config with a top-level model_provider override", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const profilePath = join(directory, "work.config.toml")
    const original = '# base config\nmodel = "gpt-5"\n'
    const profile = [
      'model_provider = "outside"',
      'model = "outside-model"',
      "",
      "[model_providers.outside]",
      'base_url = "https://outside.example.test/v1"',
      'wire_api = "responses"',
      "",
    ].join("\n")
    await Bun.write(path, original)
    await Bun.write(profilePath, profile)

    await expect(manageCodexSettings(settingsConfig(path))).rejects.toThrow(
      /profile config.*top-level model_provider.*bypass.*work\.config\.toml/i,
    )
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await readFile(profilePath, "utf8")).toBe(profile)
    expect(await Bun.file(`${path}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${path}.zero-domain.lock`).exists()).toBe(false)
  })

  test("does not mistake nested or textual profile model_provider values for a top-level override", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, "config.toml")
    const profilePath = join(directory, "work.config.toml")
    const original = '# base config\nmodel = "gpt-5"\n'
    const profile = [
      'model = "profile-model"',
      'developer_instructions = "the text model_provider is not a setting"',
      "",
      "[profile_metadata]",
      'model_provider = "nested-metadata-only"',
      "",
    ].join("\n")
    await Bun.write(path, original)
    await Bun.write(profilePath, profile)

    const session = await manageCodexSettings(settingsConfig(path))
    expect(session).toBeDefined()
    expect((await parsedConfig(path)).model_provider).toBe("zero-domain")
    expect(await readFile(profilePath, "utf8")).toBe(profile)

    await session?.restore()
    expect(await readFile(path, "utf8")).toBe(original)
    expect(await readFile(profilePath, "utf8")).toBe(profile)
  })
})

async function parsedConfig(path: string) {
  return parse(await readFile(path, "utf8")) as Record<string, unknown>
}

async function temporaryDirectory() {
  const path = await mkdtemp(join(tmpdir(), "zero-domain-codex-settings-test-"))
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
    claudeSettingsAuto: false,
    claudeSettingsPath: path,
    claudeProxyURL: "http://127.0.0.1:8787",
    claudeProxyAPIKey: "proxy-key",
    codexSettingsAuto: true,
    codexConfigPath: path,
    codexProxyURL: "http://127.0.0.1:8787/codex",
    codexProxyAPIKey: "codex-proxy-key",
    codexUpstreamURL: "https://api.openai.com/v1",
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
