import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createProxy } from "../src/proxy"
import type { ProxyConfig } from "../src/config"

/**
 * 端到端集成：真正启动 createProxy + mock upstream（不再依赖本机 18787 幽灵服务）
 */

const servers: Array<ReturnType<typeof Bun.serve>> = []

afterAll(async () => {
  for (const server of servers.splice(0)) server.stop(true)
})

function config(dir: string, upstreamURL: string): ProxyConfig {
  return {
    listenHost: "127.0.0.1",
    listenPort: 0,
    upstreamURL,
    upstreamAPIKey: "upstream-key",
    upstreamAuthMode: "anthropic",
    upstreamSource: "static",
    ccswitchSettingsPath: join(dir, "settings.json"),
    claudeSettingsAuto: false,
    claudeSettingsPath: join(dir, "claude-settings.json"),
    claudeProxyURL: "http://127.0.0.1:8787",
    claudeProxyAPIKey: "proxy-key",
    codexSettingsAuto: false,
    codexConfigPath: join(dir, "codex.toml"),
    codexProxyURL: "http://127.0.0.1:8787/codex",
    codexProxyAPIKey: "proxy-key",
    codexUpstreamExplicit: false,
    proxyAPIKey: "test-proxy-key",
    proxyAuthPassthrough: false,
    adminToken: "test-admin-token",
    maxRequestBytes: 1024 * 1024,
    upstreamTimeoutMs: 5_000,
    reviewMode: "off",
    reviewScope: "api",
    judgeEnabled: false,
    judgeProvider: "openai-chat",
    judgeBaseURL: "https://example.test",
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
    disconnectOnBlock: false,
    auditPath: join(dir, "audit.jsonl"),
    auditIncludeBody: "off",
    auditStdout: "off",
    adminConfigPath: join(dir, "zero-domain.config.json"),
  }
}

describe("端到端脱敏还原集成测试", () => {
  test("通过代理发送含敏感信息的请求并还原响应", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zero-domain-e2e-"))
    let captured = ""
    const upstream = Bun.serve({
      port: 0,
      fetch: async (req) => {
        const body = await req.text()
        captured = body
        return Response.json({
          id: "msg_test",
          type: "message",
          role: "assistant",
          content: [{ type: "text", text: `收到请求: ${body}` }],
        })
      },
    })
    servers.push(upstream)

    const proxy = createProxy(config(dir, `http://127.0.0.1:${upstream.port}`))
    const sensitiveData = {
      model: "claude-opus-4",
      messages: [
        {
          role: "user",
          content:
            "我的服务器 IP 是 192.168.1.100，数据库连接串是 mysql://root:password@localhost:3306/db，联系电话 13812345678",
        },
      ],
      max_tokens: 1024,
    }

    const response = await proxy(
      new Request("http://proxy.test/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "test-proxy-key",
        },
        body: JSON.stringify(sensitiveData),
      }),
    )

    expect(response.ok).toBe(true)
    const result = (await response.json()) as { content: Array<{ text: string }> }
    const responseText = result.content[0].text

    // 客户端看到还原后的敏感信息
    expect(responseText).toContain("192.168.1.100")
    expect(responseText).toContain("mysql://root:password@localhost:3306/db")
    expect(responseText).toContain("13812345678")
    expect(responseText).not.toMatch(/\{\{IP_[a-f0-9]{8}\}\}/)
    expect(responseText).not.toMatch(/\{\{CONNSTR_[a-f0-9]{8}\}\}/)
    expect(responseText).not.toMatch(/\{\{PHONE_[a-f0-9]{8}\}\}/)

    // 上游只看到脱敏后的内容
    expect(captured).not.toContain("192.168.1.100")
    expect(captured).not.toContain("mysql://root:password@localhost:3306/db")
    expect(captured).toMatch(/\{\{[A-Z_]+_[a-f0-9]{8}\}\}/)

    await rm(dir, { recursive: true, force: true })
  })

  test("验证上游收到的是脱敏后的数据", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zero-domain-e2e-"))
    let capturedUpstreamBody = ""
    const upstream = Bun.serve({
      port: 0,
      fetch: async (req) => {
        capturedUpstreamBody = await req.text()
        return Response.json({
          id: "msg_test",
          type: "message",
          role: "assistant",
          content: [{ type: "text", text: "OK" }],
        })
      },
    })
    servers.push(upstream)

    const proxy = createProxy(config(dir, `http://127.0.0.1:${upstream.port}`))
    await proxy(
      new Request("http://proxy.test/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "test-proxy-key",
        },
        body: JSON.stringify({
          model: "claude-opus-4",
          messages: [{ role: "user", content: "IP: 10.0.0.1" }],
          max_tokens: 1024,
        }),
      }),
    )

    expect(capturedUpstreamBody).not.toContain("10.0.0.1")
    expect(capturedUpstreamBody).toMatch(/\{\{IP_[a-f0-9]{8}\}\}/)
    await rm(dir, { recursive: true, force: true })
  })
})

describe("独立单元测试（无需启动服务器）", () => {
  test("验证脱敏逻辑", async () => {
    const { sanitize, cleanupMapping } = await import("../src/sanitizer")
    const id = crypto.randomUUID()
    const result = sanitize("contact 13812345678", id)
    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{PHONE_[a-f0-9]{8}\}\}/)
    cleanupMapping(id)
  })

  test("验证还原逻辑", async () => {
    const { sanitize, restore, cleanupMapping } = await import("../src/sanitizer")
    const id = crypto.randomUUID()
    const result = sanitize("ip 10.0.0.1", id)
    const restored = restore(result.sanitized, id)
    const text = typeof restored === "string" ? restored : new TextDecoder().decode(restored)
    expect(text).toContain("10.0.0.1")
    cleanupMapping(id)
  })
})
