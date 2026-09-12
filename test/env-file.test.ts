import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

// 在临时目录中模拟项目根（.env 用 process.cwd() 解析，测试通过 chdir 切换）
let workDir: string
let originalCwd: string

beforeAll(async () => {
  originalCwd = process.cwd()
  workDir = await mkdtemp(join(tmpdir(), "zero-domain-env-test-"))
  process.chdir(workDir)
})

afterAll(async () => {
  process.chdir(originalCwd)
  await rm(workDir, { recursive: true, force: true })
})

// 最小化 admin API 处理器导入（直接测 handleAdminAPI 的 env-file 分支）
import { handleAdminAPI } from "../src/admin"
import type { ProxyConfig } from "../src/config"

function makeConfig(auditPath: string): ProxyConfig {
  return {
    listenHost: "127.0.0.1",
    listenPort: 8787,
    upstreamURL: "https://api.anthropic.com",
    upstreamAuthMode: "anthropic",
    upstreamSource: "static",
    ccswitchSettingsPath: "",
    claudeSettingsAuto: false,
    claudeSettingsPath: "",
    claudeProxyAPIKey: "",
    codexSettingsAuto: false,
    codexConfigPath: "",
    codexProxyAPIKey: "",
    codexUpstreamExplicit: false,
    proxyAPIKey: "proxy-key",
    proxyAuthPassthrough: false,
    adminToken: "admin-key",
    maxRequestBytes: 1024 * 1024,
    upstreamTimeoutMs: 120000,
    reviewMode: "llm",
    reviewScope: "all",
    judgeEnabled: true,
    judgeProvider: "anthropic",
    judgeBaseURL: "https://api.anthropic.com",
    judgeModel: "claude-haiku-4-5-20251001",
    judgeTimeoutMs: 8000,
    judgeMaxOutputTokens: 512,
    judgeMaxInputChars: 24000,
    judgeMaxMessages: 12,
    judgeMaxConcurrent: 2,
    judgeMinIntervalMs: 100,
    judgeQueueSize: 32,
    judgeQueueBytes: 67108864,
    judgeMaxRetries: 2,
    judgeRetryBaseMs: 250,
    judgeFailOpen: false,
    disconnectOnBlock: false,
    auditPath,
    auditIncludeBody: "off",
    auditStdout: "off",
  } as ProxyConfig
}

describe("env-file API", () => {
  test("GET 返回不存在状态（无 .env 文件时）", async () => {
    const config = makeConfig(join(workDir, "audit.jsonl"))
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        headers: { authorization: "Bearer admin-key" },
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res).not.toBeUndefined()
    expect(res!.status).toBe(200)
    const body = (await res!.json()) as { exists: boolean; path: string }
    expect(body.exists).toBe(false)
    expect(body.path).toBe(resolve(workDir, ".env"))
  })

  test("PUT 创建 .env 并自动备份，重复 PUT 覆盖时保留备份", async () => {
    const envPath = join(workDir, ".env")
    const backupPath = `${envPath}.zero-domain-backup`
    const config = makeConfig(join(workDir, "audit.jsonl"))

    // 先放一个旧 .env 以验证备份
    await writeFile(envPath, "OLD_KEY=old-value\n", "utf8")

    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ content: "# comment\nLISTEN_PORT=9999\nUPSTREAM_URL=https://x.test\n" }),
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res!.status).toBe(200)
    const body = (await res!.json()) as { saved: boolean; restartRequired: boolean }
    expect(body.saved).toBe(true)
    expect(body.restartRequired).toBe(true)

    // 原文件已更新
    expect(await readFile(envPath, "utf8")).toContain("LISTEN_PORT=9999")
    // 备份保留旧内容
    expect(await readFile(backupPath, "utf8")).toBe("OLD_KEY=old-value\n")
  })

  test("PUT 拒绝语法错误行", async () => {
    const config = makeConfig(join(workDir, "audit.jsonl"))
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ content: "VALID=1\nthis is not valid\n" }),
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res!.status).toBe(400)
    const body = (await res!.json()) as { error: string }
    expect(body.error).toContain("第 2 行")
  })

  test("PUT 写入产生审计记录", async () => {
    const auditPath = join(workDir, "audit-env.jsonl")
    const config = makeConfig(auditPath)
    await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ content: "A=1\n" }),
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    const audit = await readFile(auditPath, "utf8")
    expect(audit).toContain("/admin/api/env-file")
    expect(audit).toContain("环境配置文件已更新")
  })

  test("无 token 时返回 401", async () => {
    const config = makeConfig(join(workDir, "audit.jsonl"))
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file"),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res!.status).toBe(401)
  })

  test("PUT 拒绝 LISTEN_HOST / AUDIT_PATH 等危险键", async () => {
    const config = makeConfig(join(workDir, "audit.jsonl"))
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ content: "LISTEN_HOST=0.0.0.0\nAUDIT_PATH=/tmp/x\n" }),
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res!.status).toBe(400)
    const body = (await res!.json()) as { error: string }
    expect(body.error).toMatch(/LISTEN_HOST|AUDIT_PATH/)
  })

  test("PUT 拒绝空 PROXY_API_KEY", async () => {
    const config = makeConfig(join(workDir, "audit.jsonl"))
    const res = await handleAdminAPI(
      new Request("http://proxy.test/admin/api/env-file", {
        method: "PUT",
        headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
        body: JSON.stringify({ content: 'PROXY_API_KEY=""\n' }),
      }),
      new URL("http://proxy.test/admin/api/env-file"),
      config,
    )
    expect(res!.status).toBe(400)
    expect(((await res!.json()) as { error: string }).error).toContain("不能为空")
  })

  test("GET 对密钥字段脱敏", async () => {
    await writeFile(join(workDir, ".env"), "PROXY_API_KEY=secret-value\nLISTEN_PORT=1\n", "utf8")
    const config = makeConfig(join(workDir, "audit.jsonl"))
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
    expect(body.content).not.toContain("secret-value")
  })
})
