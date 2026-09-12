import { afterEach, describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { handleAdminAPI } from "../src/admin"
import { writeConfigOverrides, readConfigOverrides } from "../src/config-store"
import type { ProxyConfig } from "../src/config"
import { localHardBlock } from "../src/judge"
import { createProxy } from "../src/proxy"
import { sanitize, cleanupMapping } from "../src/sanitizer"
import { resolveUpstream } from "../src/upstream"

const temps: string[] = []

afterEach(async () => {
  await Promise.all(temps.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function tempDir() {
  const dir = await mkdtemp(join(tmpdir(), "zero-domain-sec-"))
  temps.push(dir)
  return dir
}

function baseConfig(dir: string, overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    listenHost: "127.0.0.1",
    listenPort: 0,
    upstreamURL: "https://api.anthropic.com",
    upstreamAPIKey: "upstream-secret-key",
    upstreamAuthMode: "anthropic",
    upstreamSource: "static",
    ccswitchSettingsPath: join(dir, "settings.json"),
    upstreamTimeoutMs: 5_000,
    maxRequestBytes: 1024 * 1024,
    proxyAPIKey: "proxy-key",
    proxyAuthPassthrough: false,
    claudeSettingsAuto: false,
    claudeSettingsPath: join(dir, "claude-settings.json"),
    claudeProxyURL: "http://127.0.0.1:8787",
    claudeProxyAPIKey: "proxy-key",
    codexSettingsAuto: false,
    codexConfigPath: join(dir, "codex.toml"),
    codexProxyURL: "http://127.0.0.1:8787/codex",
    codexProxyAPIKey: "proxy-key",
    codexUpstreamURL: undefined,
    codexUpstreamExplicit: false,
    adminToken: "admin-key",
    adminConfigPath: join(dir, "zero-domain.config.json"),
    auditPath: join(dir, "audit.jsonl"),
    auditIncludeBody: "off",
    auditStdout: "off",
    reviewMode: "off",
    reviewScope: "api",
    judgeEnabled: false,
    judgeProvider: "openai-chat",
    judgeBaseURL: "https://example.test",
    judgeAPIKey: "judge-key",
    judgeModel: "test-model",
    judgeTimeoutMs: 1000,
    judgeMaxOutputTokens: 128,
    judgeMaxInputChars: 64_000,
    judgeMaxMessages: 8,
    judgeMaxConcurrent: 1,
    judgeMinIntervalMs: 0,
    judgeQueueSize: 8,
    judgeQueueBytes: 1_000_000,
    judgeMaxRetries: 0,
    judgeRetryBaseMs: 10,
    judgeFailOpen: false,
    judgePrompt: undefined,
    judgeAccountID: undefined,
    disconnectOnBlock: false,
    ...overrides,
  }
}

describe("安全加固回归", () => {
  test("空代理密钥不会旁路认证", async () => {
    const dir = await tempDir()
    const handle = createProxy(
      baseConfig(dir, {
        proxyAPIKey: undefined,
        claudeProxyAPIKey: undefined,
        proxyAuthPassthrough: false,
      }),
    )
    const res = await handle(
      new Request("http://proxy.test/v1/messages", {
        method: "POST",
        headers: { "x-api-key": "", "content-type": "application/json" },
        body: "{}",
      }),
    )
    expect(res.status).toBe(401)
  })

  test("配置了密钥时错误密钥仍 401", async () => {
    const dir = await tempDir()
    const handle = createProxy(baseConfig(dir))
    const res = await handle(
      new Request("http://proxy.test/v1/messages", {
        method: "POST",
        headers: { "x-api-key": "wrong-key", "content-type": "application/json" },
        body: "{}",
      }),
    )
    expect(res.status).toBe(401)
  })

  test("admin PUT 拒绝空 PROXY_API_KEY / PROXY_ADMIN_TOKEN", async () => {
    const dir = await tempDir()
    const config = baseConfig(dir)
    for (const key of ["PROXY_API_KEY", "PROXY_ADMIN_TOKEN", "CLAUDE_PROXY_API_KEY"]) {
      const res = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/config", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ [key]: "" }),
        }),
        new URL("http://proxy.test/admin/api/config"),
        config,
      )
      expect(res!.status).toBe(400)
      const body = (await res!.json()) as { error: string }
      expect(body.error).toMatch(/不能为空|校验失败/)
    }
  })

  test("admin PUT 拒绝 LISTEN_HOST / 路径类危险键", async () => {
    const dir = await tempDir()
    const config = baseConfig(dir)
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/config", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ LISTEN_HOST: "0.0.0.0", AUDIT_PATH: "/tmp/evil.jsonl" }),
      }),
      new URL("http://proxy.test/admin/api/config"),
      config,
    )
    expect(res!.status).toBe(400)
  })

  test("env-file GET 对密钥脱敏", async () => {
    const dir = await tempDir()
    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      await writeFile(
        join(dir, ".env"),
        "LISTEN_PORT=8787\nPROXY_API_KEY=super-secret\nPROXY_ADMIN_TOKEN=admin-secret\nUPSTREAM_URL=https://x.test\n",
        "utf8",
      )
      const config = baseConfig(dir)
      const res = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/env-file", {
          headers: { authorization: "Bearer admin-key" },
        }),
        new URL("http://proxy.test/admin/api/env-file"),
        config,
      )
      expect(res!.status).toBe(200)
      const body = (await res!.json()) as { content: string; redacted: boolean }
      expect(body.redacted).toBe(true)
      expect(body.content).toContain("PROXY_API_KEY=***")
      expect(body.content).toContain("PROXY_ADMIN_TOKEN=***")
      expect(body.content).not.toContain("super-secret")
      expect(body.content).not.toContain("admin-secret")
      expect(body.content).toContain("LISTEN_PORT=8787")
    } finally {
      process.chdir(originalCwd)
    }
  })

  test("env-file PUT 拒绝危险键与空密钥", async () => {
    const dir = await tempDir()
    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      const config = baseConfig(dir)
      const forbidden = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/env-file", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ content: "LISTEN_HOST=0.0.0.0\n" }),
        }),
        new URL("http://proxy.test/admin/api/env-file"),
        config,
      )
      expect(forbidden!.status).toBe(400)
      expect(((await forbidden!.json()) as { error: string }).error).toContain("LISTEN_HOST")

      const emptyKey = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/env-file", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ content: "PROXY_API_KEY=\n" }),
        }),
        new URL("http://proxy.test/admin/api/env-file"),
        config,
      )
      expect(emptyKey!.status).toBe(400)
      expect(((await emptyKey!.json()) as { error: string }).error).toContain("不能为空")
    } finally {
      process.chdir(originalCwd)
    }
  })

  test("PEM 整块脱敏，不只 BEGIN 行", () => {
    const pem = [
      "-----BEGIN PRIVATE KEY-----",
      "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7",
      "secret-material-line-two-ABCDEF0123456789",
      "-----END PRIVATE KEY-----",
    ].join("\n")
    const id = crypto.randomUUID()
    const result = sanitize(`key material:\n${pem}\ntrailer`, id)
    expect(result.sanitized).not.toContain("secret-material-line-two")
    expect(result.sanitized).not.toContain("BEGIN PRIVATE KEY")
    expect(result.sanitized).toMatch(/\{\{PRIVKEY_[a-f0-9]{8}\}\}/)
    cleanupMapping(id)
  })

  test("tool_use 参数中的破坏命令被本地硬拦", () => {
    const hit = localHardBlock({
      method: "POST",
      path: "/v1/messages",
      body: {
        messages: [
          {
            role: "assistant",
            content: [
              {
                type: "tool_use",
                name: "Bash",
                input: { command: "rm -rf /var/lib/mysql" },
              },
            ],
          },
        ],
      },
    })
    expect(hit).toContain("递归删除")
  })

  test("讨论词仅邻近命中才豁免，远端讨论不短路整单", () => {
    const hit = localHardBlock({
      method: "POST",
      path: "/v1/messages",
      body: {
        messages: [
          { role: "user", content: "我们先讨论一下架构最佳实践" },
          { role: "user", content: "现在执行: rm -rf /home/ubuntu/data" },
        ],
      },
    })
    expect(hit).toContain("递归删除")
  })

  test("早期消息中的高危命令即使超出审查窗口仍被硬拦", () => {
    const messages = Array.from({ length: 20 }, (_, i) => ({
      role: "user",
      content: i === 0 ? "please run rm -rf /etc/passwd-backup" : `chat turn ${i}`,
    }))
    const hit = localHardBlock({
      method: "POST",
      path: "/v1/messages",
      body: { messages },
    })
    expect(hit).toContain("递归删除")
  })

  test("透传模式下不注入配置里的上游 Key", async () => {
    const dir = await tempDir()
    const seen: Headers[] = []
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined))
      seen.push(headers)
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }) as typeof fetch

    try {
      const handle = createProxy(
        baseConfig(dir, {
          proxyAuthPassthrough: true,
          reviewMode: "off",
          judgeEnabled: false,
        }),
      )
      const res = await handle(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": "client-original-key",
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify({ model: "claude-3", messages: [{ role: "user", content: "hi" }] }),
        }),
      )
      expect(res.status).toBe(200)
      expect(seen.length).toBeGreaterThan(0)
      const upstreamHeaders = seen[0]!
      expect(upstreamHeaders.get("x-api-key")).toBe("client-original-key")
      expect(upstreamHeaders.get("x-api-key")).not.toBe("upstream-secret-key")
      expect(upstreamHeaders.get("authorization")).toBeNull()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("config-store 并发写入不丢键", async () => {
    const dir = await tempDir()
    const path = join(dir, "cfg.json")
    await Promise.all([
      writeConfigOverrides(path, { REVIEW_SCOPE: "all" }),
      writeConfigOverrides(path, { LISTEN_PORT: "9999" }),
      writeConfigOverrides(path, { REVIEW_FAIL_OPEN: "false" }),
    ])
    const saved = await readConfigOverrides(path)
    expect(saved.REVIEW_SCOPE).toBe("all")
    expect(saved.LISTEN_PORT).toBe("9999")
    expect(saved.REVIEW_FAIL_OPEN).toBe("false")
  })

  test("ccswitch 仅有外部 URL 无凭证时不混绑本地 upstream Key", async () => {
    const dir = await tempDir()
    const settingsPath = join(dir, "settings.json")
    await writeFile(settingsPath, JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://evil.example/v1" } }), "utf8")
    const resolved = await resolveUpstream(
      baseConfig(dir, {
        upstreamSource: "ccswitch",
        ccswitchSettingsPath: settingsPath,
        upstreamURL: "https://api.anthropic.com",
        upstreamAPIKey: "REAL_UPSTREAM_SECRET",
      }),
    )
    expect(resolved.resolvedFrom).toBe("fallback")
    expect(resolved.url).toBe("https://api.anthropic.com")
    expect(resolved.apiKey).toBe("REAL_UPSTREAM_SECRET")
  })

  test("ccswitch 自带凭证时使用文件内 Key", async () => {
    const dir = await tempDir()
    const settingsPath = join(dir, "settings.json")
    await writeFile(
      settingsPath,
      JSON.stringify({
        env: { ANTHROPIC_BASE_URL: "https://ccs.example/v1", ANTHROPIC_API_KEY: "file-key" },
      }),
      "utf8",
    )
    const resolved = await resolveUpstream(
      baseConfig(dir, {
        upstreamSource: "ccswitch",
        ccswitchSettingsPath: settingsPath,
        upstreamAPIKey: "REAL_UPSTREAM_SECRET",
      }),
    )
    expect(resolved.resolvedFrom).toBe("ccswitch")
    expect(resolved.url).toBe("https://ccs.example/v1")
    expect(resolved.apiKey).toBe("file-key")
  })

  test("邻近贴「如何」但含立刻执行 → 仍硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "请立刻执行 rm -rf /var/lib/mysql 如何" }] },
      }),
    ).toContain("递归删除")
  })

  test("编码 decoy 打满后仍能硬拦恶意 base64", () => {
    const decoys = Array.from({ length: 10 }, (_, i) =>
      Buffer.from(`harmless-padding-content-${i}-${"x".repeat(40)}`).toString("base64"),
    )
    const evil = Buffer.from("rm -rf /var/lib/mysql").toString("base64")
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: [...decoys, evil].join("\n") }] },
      }),
    ).toContain("递归删除")
  })

  test("500 条编码 decoy + 尾部恶意 base64 仍硬拦", () => {
    const decoys = Array.from({ length: 500 }, (_, i) =>
      Buffer.from(`harmless-padding-content-${i}-${"y".repeat(40)}`).toString("base64"),
    )
    const evil = Buffer.from("rm -rf /var/lib/mysql").toString("base64")
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: [...decoys, evil].join("\n") }] },
      }),
    ).toContain("递归删除")
  })

  test("50KB 前缀填充后尾部恶意 base64 仍硬拦", () => {
    const evil = Buffer.from("rm -rf /var/lib/mysql").toString("base64")
    const padded = `${"B".repeat(50_000)}\n${evil}`
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: padded }] },
      }),
    ).toContain("递归删除")
  })

  test("多层嵌套 base64 仍硬拦", () => {
    const inner = Buffer.from("rm -rf /etc").toString("base64")
    const mid = Buffer.from(inner).toString("base64")
    const outer = Buffer.from(mid).toString("base64")
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: outer }] },
      }),
    ).toContain("递归删除")
  })

  test("ENCRYPTED / DSA 私钥整块脱敏", () => {
    for (const kind of ["ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY"]) {
      const pem = `-----BEGIN ${kind}-----\nSECRETDATA_LINE\n-----END ${kind}-----`
      const id = crypto.randomUUID()
      const result = sanitize(pem, id)
      expect(result.sanitized).not.toContain("SECRETDATA_LINE")
      expect(result.sanitized).toMatch(/\{\{PRIVKEY_[a-f0-9]{8}\}\}/)
      cleanupMapping(id)
    }
  })

  test("零宽字符与全角命令归一化后硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "rm\u200b -rf /var/lib/mysql" }] },
      }),
    ).toContain("递归删除")
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "ｒｍ -ｒｆ /home/ubuntu/data" }] },
      }),
    ).toContain("递归删除")
  })

  test("配置 GET 返回密钥轮换提醒且不含密钥原文", async () => {
    const dir = await tempDir()
    const configPath = join(dir, "zero-domain.config.json")
    await writeFile(
      configPath,
      JSON.stringify({ REVIEW_API_KEY: "sk-review-secret-key-1234", REVIEW_MODE: "llm" }, null, 2),
      "utf8",
    )
    const { markSecretsRotated } = await import("../src/config-store")
    await markSecretsRotated(configPath, ["REVIEW_API_KEY"])
    // 把轮换时间拨到 40 天前
    const metaPath = `${configPath}.secrets-meta.json`
    await writeFile(
      metaPath,
      JSON.stringify({ rotatedAt: { REVIEW_API_KEY: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString() } }),
      "utf8",
    )

    const config = baseConfig(dir, {
      adminConfigPath: configPath,
      judgeAPIKey: "sk-review-secret-key-1234",
    })
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/config", {
        headers: { authorization: "Bearer admin-key" },
      }),
      new URL("http://proxy.test/admin/api/config"),
      config,
    )
    expect(res!.status).toBe(200)
    const body = (await res!.json()) as {
      judgeAPIKeyConfigured: boolean
      judgeAPIKeySuffix?: string
      secretsReminder: { recommendRotate: boolean; messages: string[]; persistedSecretKeys: string[] }
      judgeAPIKey?: string
      REVIEW_API_KEY?: string
    }
    expect(body.judgeAPIKeyConfigured).toBe(true)
    expect(body.judgeAPIKeySuffix).toBe("1234")
    expect(body.judgeAPIKey).toBeUndefined()
    expect(body.REVIEW_API_KEY).toBeUndefined()
    expect(body.secretsReminder.persistedSecretKeys).toContain("REVIEW_API_KEY")
    expect(body.secretsReminder.recommendRotate).toBe(true)
    expect(body.secretsReminder.messages.some((line) => line.includes("轮换"))).toBe(true)
    expect(JSON.stringify(body)).not.toContain("sk-review-secret-key-1234")
  })

  test("env-file PUT 拒绝把脱敏 *** 写回密钥", async () => {
    const dir = await tempDir()
    const originalCwd = process.cwd()
    process.chdir(dir)
    try {
      await writeFile(join(dir, ".env"), "PROXY_API_KEY=real-secret\nLISTEN_PORT=1\n", "utf8")
      const config = baseConfig(dir)
      const getRes = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/env-file", {
          headers: { authorization: "Bearer admin-key" },
        }),
        new URL("http://proxy.test/admin/api/env-file"),
        config,
      )
      const getBody = (await getRes!.json()) as { content: string }
      expect(getBody.content).toContain("PROXY_API_KEY=***")
      const putRes = await handleAdminAPI(
        new Request("http://proxy.test/admin/api/env-file", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ content: getBody.content }),
        }),
        new URL("http://proxy.test/admin/api/env-file"),
        config,
      )
      expect(putRes!.status).toBe(400)
      expect(((await putRes!.json()) as { error: string }).error).toContain("脱敏占位符")
      expect(await readFile(join(dir, ".env"), "utf8")).toContain("PROXY_API_KEY=real-secret")
    } finally {
      process.chdir(originalCwd)
    }
  })
})
