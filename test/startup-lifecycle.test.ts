import { afterEach, describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, unlink } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { manageClaudeSettings } from "../src/claude-settings"
import { manageCodexSettings } from "../src/codex-settings"
import { loadConfig } from "../src/config"

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe("startup settings transaction", () => {
  test("restores Claude immediately when Codex takeover fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "zero-domain-startup-test-"))
    directories.push(directory)
    const claudePath = join(directory, "claude", "settings.json")
    const codexPath = join(directory, "codex", "config.toml")
    const originalClaude = `${JSON.stringify({ env: { KEEP: "yes" }, theme: "dark" }, null, 2)}\n`
    await Bun.write(claudePath, originalClaude)
    await Bun.write(codexPath, 'model_provider = "unterminated\n')

    const child = Bun.spawn([process.execPath, "run", "src/index.ts"], {
      cwd: resolve(import.meta.dir, ".."),
      env: {
        ...process.env,
        LISTEN_HOST: "127.0.0.1",
        LISTEN_PORT: "0",
        UPSTREAM_SOURCE: "static",
        UPSTREAM_URL: "https://api.anthropic.com",
        UPSTREAM_AUTH_MODE: "preserve",
        CLAUDE_SETTINGS_AUTO: "true",
        CLAUDE_SETTINGS_PATH: claudePath,
        CLAUDE_PROXY_URL: "",
        CODEX_SETTINGS_AUTO: "true",
        CODEX_CONFIG_PATH: codexPath,
        CODEX_PROXY_URL: "",
        CODEX_UPSTREAM_URL: "",
        PROXY_API_KEY: "startup-proxy-key",
        PROXY_ADMIN_TOKEN: "startup-admin-key",
        REVIEW_MODE: "off",
        AUDIT_PATH: join(directory, "audit.jsonl"),
        ADMIN_CONFIG_PATH: join(directory, "admin.json"),
      },
      stdout: "pipe",
      stderr: "pipe",
    })

    expect(await child.exited).not.toBe(0)
    expect(await readFile(claudePath, "utf8")).toBe(originalClaude)
    expect(await Bun.file(`${claudePath}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${claudePath}.zero-domain.lock`).exists()).toBe(false)
    expect(await Bun.file(`${codexPath}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${codexPath}.zero-domain.lock`).exists()).toBe(false)
  })

  test("recovers stale client settings even when unrelated service config is invalid", async () => {
    const directory = await mkdtemp(join(tmpdir(), "zero-domain-recovery-test-"))
    directories.push(directory)
    const claudePath = join(directory, "claude", "settings.json")
    const codexPath = join(directory, "codex", "config.toml")
    const adminPath = join(directory, "admin.json")
    const originalClaude = `${JSON.stringify({ env: { KEEP: "yes" } }, null, 2)}\n`
    const originalCodex = [
      'model_provider = "custom"',
      "",
      "[model_providers.custom]",
      'base_url = "https://provider.example.test"',
      'wire_api = "responses"',
      "",
    ].join("\n")
    await Bun.write(claudePath, originalClaude)
    await Bun.write(codexPath, originalCodex)

    const config = loadConfig({
      UPSTREAM_URL: "https://api.anthropic.com",
      UPSTREAM_AUTH_MODE: "preserve",
      PROXY_API_KEY: "recovery-proxy-key",
      PROXY_ADMIN_TOKEN: "recovery-admin-key",
      REVIEW_MODE: "off",
      CLAUDE_SETTINGS_AUTO: "true",
      CLAUDE_SETTINGS_PATH: claudePath,
      CLAUDE_PROXY_URL: "http://127.0.0.1:8787",
      CODEX_SETTINGS_AUTO: "true",
      CODEX_CONFIG_PATH: codexPath,
      CODEX_PROXY_URL: "http://127.0.0.1:8787/codex",
    })
    const claudeSession = await manageClaudeSettings(config)
    const codexSession = await manageCodexSettings(config)
    await unlink(`${claudePath}.zero-domain.lock`)
    await unlink(`${codexPath}.zero-domain.lock`)
    await Bun.write(adminPath, `${JSON.stringify({
      CLAUDE_SETTINGS_PATH: claudePath,
      CODEX_CONFIG_PATH: codexPath,
    })}\n`)

    const child = Bun.spawn([process.execPath, "run", "src/recover-claude-settings.ts"], {
      cwd: resolve(import.meta.dir, ".."),
      env: {
        ...process.env,
        UPSTREAM_URL: "not-an-http-url",
        PROXY_API_KEY: "",
        PROXY_ADMIN_TOKEN: "",
        CLAUDE_SETTINGS_AUTO: "false",
        CLAUDE_SETTINGS_PATH: join(directory, "wrong-claude.json"),
        CODEX_SETTINGS_AUTO: "false",
        CODEX_CONFIG_PATH: join(directory, "wrong-codex.toml"),
        ADMIN_CONFIG_PATH: adminPath,
      },
      stdout: "pipe",
      stderr: "pipe",
    })

    expect(await child.exited).toBe(0)
    expect(await readFile(claudePath, "utf8")).toBe(originalClaude)
    expect(await readFile(codexPath, "utf8")).toBe(originalCodex)
    expect(await Bun.file(`${claudePath}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${codexPath}.zero-domain.backup`).exists()).toBe(false)
    void claudeSession
    void codexSession
  })

  test("continues Codex recovery when Claude recovery fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "zero-domain-independent-recovery-test-"))
    directories.push(directory)
    const claudePath = join(directory, "claude", "settings.json")
    const codexPath = join(directory, "codex", "config.toml")
    const originalClaude = `${JSON.stringify({ env: { KEEP: "yes" } }, null, 2)}\n`
    const originalCodex = [
      'model_provider = "custom"',
      "",
      "[model_providers.custom]",
      'base_url = "https://provider.example.test"',
      'wire_api = "responses"',
      "",
    ].join("\n")
    await Bun.write(claudePath, originalClaude)
    await Bun.write(codexPath, originalCodex)

    const config = loadConfig({
      UPSTREAM_URL: "https://api.anthropic.com",
      UPSTREAM_AUTH_MODE: "preserve",
      PROXY_API_KEY: "recovery-proxy-key",
      PROXY_ADMIN_TOKEN: "recovery-admin-key",
      REVIEW_MODE: "off",
      CLAUDE_SETTINGS_AUTO: "true",
      CLAUDE_SETTINGS_PATH: claudePath,
      CLAUDE_PROXY_URL: "http://127.0.0.1:8787",
      CODEX_SETTINGS_AUTO: "true",
      CODEX_CONFIG_PATH: codexPath,
      CODEX_PROXY_URL: "http://127.0.0.1:8787/codex",
    })
    const claudeSession = await manageClaudeSettings(config)
    const codexSession = await manageCodexSettings(config)
    await unlink(`${codexPath}.zero-domain.lock`)

    const child = Bun.spawn([process.execPath, "run", "src/recover-claude-settings.ts"], {
      cwd: resolve(import.meta.dir, ".."),
      env: {
        ...process.env,
        CLAUDE_SETTINGS_PATH: claudePath,
        CODEX_CONFIG_PATH: codexPath,
        ADMIN_CONFIG_PATH: join(directory, "missing-admin.json"),
      },
      stdout: "pipe",
      stderr: "pipe",
    })

    expect(await child.exited).toBe(1)
    expect(await readFile(codexPath, "utf8")).toBe(originalCodex)
    expect(await Bun.file(`${codexPath}.zero-domain.backup`).exists()).toBe(false)
    expect(await Bun.file(`${claudePath}.zero-domain.backup`).exists()).toBe(true)

    await claudeSession?.restore()
    expect(await readFile(claudePath, "utf8")).toBe(originalClaude)
    void codexSession
  })
})
