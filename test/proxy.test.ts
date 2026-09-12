import { afterEach, describe, expect, test } from "bun:test"
import { appendFile, mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { ProxyConfig } from "../src/config"
import { loadConfig } from "../src/config"
import { createProxy } from "../src/proxy"
import { parseVerdict } from "../src/judge"

const servers: Array<{ stop(): void }> = []

afterEach(() => {
  for (const server of servers.splice(0)) server.stop()
})

describe("zero-domain", () => {
  test("keeps the existing ALLOW/BLOCK parsing boundary", () => {
    expect(parseVerdict("ALLOW")).toEqual({ allowed: true, reason: "", recognized: true })
    expect(parseVerdict("BLOCK: delete business data\nextra")).toEqual({
      allowed: false,
      reason: "delete business data",
      recognized: true,
    })
    expect(parseVerdict("unexpected output")).toEqual({
      allowed: false,
      reason: "审查响应无法识别",
      recognized: false,
    })
  })

  test("parses REVIEW as an escalation request instead of an allow", () => {
    expect(parseVerdict("REVIEW: missing context")).toEqual({
      allowed: false,
      reason: "missing context",
      recognized: true,
      needsReview: true,
    })
  })

  test("sends an uncertain initial verdict through a second review", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let judgeCalls = 0
    const systems: string[] = []
    const judge = startServer(async (request) => {
      const payload = (await request.json()) as {
        messages?: Array<{ role?: string; content?: string }>
      }
      systems.push(payload.messages?.find((message) => message.role === "system")?.content ?? "")
      judgeCalls++
      return judgeCalls === 1
        ? Response.json({ choices: [{ message: { content: "REVIEW: ambiguous" } }] })
        : Response.json({ choices: [{ message: { content: "ALLOW" } }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(auditPath, serverPort(judge), serverPort(upstream))
    proxyConfig.judgeProvider = "openai-chat"

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "uncertain" }] }),
        }),
      )

      expect(response.status).toBe(200)
      expect(judgeCalls).toBe(2)
      expect(systems[0]).toContain("升级 REVIEW")
      expect(systems[0]).toContain("只回复一行")
      expect(systems[1]).toContain("这是二审")
      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.judgeAttempts).toBe(2)
      expect(record.judgeReviewEscalated).toBe(true)
      expect(record.outcome).toBe("forwarded")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("keeps a request blocked when the second review remains uncertain", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let upstreamCalls = 0
    let judgeCalls = 0
    const judge = startServer(() => {
      judgeCalls++
      return Response.json({ choices: [{ message: { content: "REVIEW: still ambiguous" } }] })
    })
    const upstream = startServer(() => {
      upstreamCalls++
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(auditPath, serverPort(judge), serverPort(upstream))
    proxyConfig.judgeProvider = "openai-chat"

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "uncertain" }] }),
        }),
      )

      expect(response.status).toBe(403)
      expect(upstreamCalls).toBe(0)
      expect(judgeCalls).toBe(2)
      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.reason).toContain("二审未决")
      expect(record.judgeReviewEscalated).toBe(true)
      expect(record.outcome).toBe("blocked")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("blocks before contacting the upstream and writes an audit record", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let upstreamCalls = 0
    const upstream = startServer(() => {
      upstreamCalls++
      return Response.json({ forwarded: true })
    })
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "BLOCK: delete business data" }] }))
    const proxy = createProxy(config(auditPath, serverPort(judge), serverPort(upstream)))

    try {
      const response = await proxy(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-sonnet", messages: [{ role: "user", content: "delete order" }] }),
        }),
      )

      expect(response.status).toBe(403)
      expect(upstreamCalls).toBe(0)
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line))
      expect(records[0].verdict).toBe("block")
      expect(records[0].outcome).toBe("blocked")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("fails closed when the review provider returns an unrecognized response", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let upstreamCalls = 0
    const judge = startServer(() => Response.json({ unexpected: "shape" }))
    const upstream = startServer(() => {
      upstreamCalls++
      return Response.json({ forwarded: true })
    })

    try {
      const response = await createProxy(config(auditPath, serverPort(judge), serverPort(upstream)))(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: "{}",
        }),
      )

      expect(response.status).toBe(403)
      expect(upstreamCalls).toBe(0)
      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.outcome).toBe("error")
      expect(record.reason).toBe("审查响应无法识别")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("prints only the compact Chinese blocked summary", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "BLOCK: delete business data" }] }))
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(auditPath, serverPort(judge), serverPort(upstream))
    proxyConfig.auditStdout = "blocked"
    const lines: string[] = []
    const originalLog = console.log
    console.log = (...args: unknown[]) => lines.push(args.join(" "))

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-sonnet", messages: [{ role: "user", content: "delete order" }] }),
        }),
      )

      expect(response.status).toBe(403)
      const output = lines.find((line) => line.startsWith("{"))
      expect(output).toBeDefined()
      const summary = JSON.parse(output!)
      expect(Object.keys(summary)).toEqual([
        "判定",
        "原因",
        "结果",
        "审查模型",
        "审查尝试次数",
        "审查排队毫秒",
        "耗时毫秒",
      ])
      expect(summary).toMatchObject({
        判定: "拦截",
        原因: "delete business data",
        结果: "已拦截",
        审查模型: proxyConfig.judgeModel,
        审查尝试次数: 1,
        审查排队毫秒: expect.any(Number),
        耗时毫秒: expect.any(Number),
      })
      expect(summary).not.toHaveProperty("接口")
      expect(summary).not.toHaveProperty("方法")
      expect(summary).not.toHaveProperty("请求体")
      expect(output).not.toContain("[zero-domain][audit]")
      expect(JSON.parse(await readFile(auditPath, "utf8")).requestBody).toBeUndefined()
    } finally {
      console.log = originalLog
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("does not expose raw request bodies in blocked summaries", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "BLOCK: raw secret" }] }))
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.auditStdout = "blocked"
    const lines: string[] = []
    const originalLog = console.log
    console.log = (...args: unknown[]) => lines.push(args.join(" "))

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/raw", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/x-www-form-urlencoded" },
          body: "token=sample-secret&password=sample-pass",
        }),
      )

      expect(response.status).toBe(403)
      const output = lines.find((line) => line.startsWith("{"))
      expect(output).toBeDefined()
      expect(output).not.toContain("sample-secret")
      expect(output).not.toContain("sample-pass")
      const summary = JSON.parse(output!)
      expect(Object.keys(summary)).toEqual([
        "判定",
        "原因",
        "结果",
        "审查模型",
        "审查尝试次数",
        "审查排队毫秒",
        "耗时毫秒",
      ])
      expect(summary).not.toHaveProperty("请求体")
      expect(output).not.toContain("[zero-domain][audit]")
    } finally {
      console.log = originalLog
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("can close the HTTP/1.1 connection after a block", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "BLOCK: stop service" }] }))
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.disconnectOnBlock = true

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-sonnet", messages: [{ role: "user", content: "stop service" }] }),
        }),
      )

      expect(response.status).toBe(403)
      expect(response.headers.get("connection")).toBe("close")
      expect(await response.text()).toBe("")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("forwards an allowed request and preserves an SSE response", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    const upstream = startServer(
      () =>
        new Response("event: message_start\ndata: {}\n\n", {
          headers: { "content-type": "text/event-stream" },
        }),
    )
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "ALLOW" }] }))
    const proxy = createProxy(config(auditPath, serverPort(judge), serverPort(upstream)))

    try {
      const response = await proxy(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "hello" }], stream: true }),
        }),
      )

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toContain("text/event-stream")
      expect(await response.text()).toContain("event: message_start")
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line))
      expect(records[0].verdict).toBe("allow")
      expect(records[0].outcome).toBe("forwarded")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("keeps a streaming body open after the upstream header timeout", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let cancelled = false
    const upstream = startServer(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("first\n"))
              setTimeout(() => {
                if (cancelled) return
                controller.enqueue(new TextEncoder().encode("second\n"))
                controller.close()
              }, 80)
            },
            cancel() {
              cancelled = true
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        ),
    )
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, serverPort(upstream))
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false
    proxyConfig.upstreamTimeoutMs = 20

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/stream", { headers: { authorization: "Bearer proxy-key" } }),
      )
      expect(await response.text()).toBe("first\nsecond\n")
      expect(cancelled).toBe(false)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("sends a bounded text-only review projection", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let reviewPrompt = ""
    let upstreamBody: Record<string, unknown> | undefined
    const judge = startServer(async (request) => {
      const payload = (await request.json()) as { messages?: Array<{ content?: string }> }
      reviewPrompt = payload.messages?.[0]?.content ?? ""
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(async (request) => {
      upstreamBody = (await request.json()) as Record<string, unknown>
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxMessages = 2
    proxyConfig.judgeMaxInputChars = 400

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({
            model: "claude-haiku",
            system: [{ type: "text", text: "system guidance" }],
            messages: [
              { role: "user", content: "old message" },
              { role: "assistant", content: [{ type: "text", text: "recent answer" }] },
              { role: "user", content: [{ type: "text", text: "latest message " + "x".repeat(500) }] },
            ],
            tools: [{ name: "SECRET_TOOL_SCHEMA", description: "SECRET_TOOL_DESCRIPTION" }],
            thinking: { type: "enabled", value: "SECRET_THINKING" },
            cache_control: { type: "ephemeral", value: "SECRET_CACHE" },
          }),
        }),
      )

      expect(response.status).toBe(200)
      expect(reviewPrompt).toContain('"model":"claude-haiku"')
      expect(reviewPrompt).toContain("recent answer")
      expect(reviewPrompt).toContain("latest message")
      expect(reviewPrompt).not.toContain("old message")
      expect(reviewPrompt).not.toContain("SECRET_TOOL_SCHEMA")
      expect(reviewPrompt).not.toContain("SECRET_THINKING")
      expect(reviewPrompt).not.toContain("SECRET_CACHE")
      expect(reviewPrompt).toContain("...[truncated]...")
      expect(upstreamBody?.tools).toEqual([{ name: "SECRET_TOOL_SCHEMA", description: "SECRET_TOOL_DESCRIPTION" }])
      expect((upstreamBody?.messages as Array<{ content: Array<{ text: string }> }>)[2]?.content[0]?.text).toHaveLength(
        515,
      )
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("reviews GET query targets outside the API path list", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let reviewPrompt = ""
    let upstreamURL = ""
    const judge = startServer(async (request) => {
      const payload = (await request.json()) as { messages?: Array<{ content?: string }> }
      reviewPrompt = payload.messages?.[0]?.content ?? ""
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer((request) => {
      upstreamURL = request.url
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(auditPath, serverPort(judge), serverPort(upstream))

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/api/query?sql=DROP%20TABLE%20users&token=secret-token", {
          method: "GET",
          headers: { authorization: "Bearer proxy-key" },
        }),
      )

      expect(response.status).toBe(200)
      expect(reviewPrompt).toContain("HTTP method: GET")
      expect(reviewPrompt).toContain("DROP+TABLE+users")
      expect(reviewPrompt).toContain("token=%5BREDACTED%5D")
      expect(upstreamURL).toContain("sql=DROP%20TABLE%20users")
      expect(upstreamURL).toContain("token=secret-token")

      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.requestTarget).toBe("/api/query?sql=DROP+TABLE+users&token=%5BREDACTED%5D")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("keeps high-risk values visible to the review model while redacting audit targets", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    let reviewPrompt = ""
    const judge = startServer(async (request) => {
      const payload = (await request.json()) as { messages?: Array<{ content?: string }> }
      reviewPrompt = payload.messages?.[0]?.content ?? ""
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))

    try {
      const response = await createProxy(config(auditPath, serverPort(judge), serverPort(upstream)))(
        new Request("http://proxy.test/exec?token=DROP%20TABLE%20users", {
          headers: { authorization: "Bearer proxy-key" },
        }),
      )

      expect(response.status).toBe(200)
      expect(reviewPrompt).toContain("token=DROP+TABLE+users")
      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.requestTarget).toBe("/exec?token=%5BREDACTED%5D")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("strips standard and Connection-declared hop-by-hop headers", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let forwardedProxyAuth: string | null = null
    let forwardedConnectionToken: string | null = null
    const upstream = startServer((request) => {
      forwardedProxyAuth = request.headers.get("proxy-authorization")
      forwardedConnectionToken = request.headers.get("x-leak")
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, serverPort(upstream))
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/headers", {
          headers: {
            authorization: "Bearer proxy-key",
            "proxy-authorization": "Basic sample",
            connection: "X-Leak",
            "x-leak": "sample",
          },
        }),
      )

      expect(response.status).toBe(200)
      expect(forwardedProxyAuth).toBeNull()
      expect(forwardedConnectionToken).toBeNull()
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("retries transient review provider responses", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let judgeCalls = 0
    const judge = startServer(() => {
      judgeCalls++
      if (judgeCalls === 1) return new Response("rate limited", { status: 429 })
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const auditPath = join(auditDir, "audit.jsonl")
    const proxyConfig = config(auditPath, serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxRetries = 1
    proxyConfig.judgeRetryBaseMs = 0

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "hello" }] }),
        }),
      )

      expect(response.status).toBe(200)
      expect(judgeCalls).toBe(2)
      const record = JSON.parse((await readFile(auditPath, "utf8")).trim())
      expect(record.judgeAttempts).toBe(2)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("stops retry backoff when the total review timeout expires", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let judgeCalls = 0
    const judge = startServer(() => {
      judgeCalls++
      return new Response("rate limited", { status: 429, headers: { "retry-after": "5" } })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeTimeoutMs = 40
    proxyConfig.judgeMaxRetries = 1
    const started = performance.now()

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: "{}",
        }),
      )

      expect(response.status).toBe(403)
      expect((await response.json()).error.message).toBe("审查超时")
      expect(judgeCalls).toBe(1)
      expect(performance.now() - started).toBeLessThan(500)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("limits concurrent review calls through one scheduler", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let active = 0
    let maxActive = 0
    const judge = startServer(async () => {
      active++
      maxActive = Math.max(maxActive, active)
      await new Promise((resolve) => setTimeout(resolve, 20))
      active--
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxConcurrent = 1
    proxyConfig.judgeQueueSize = 8

    try {
      const proxy = createProxy(proxyConfig)
      const responses = await Promise.all(
        Array.from({ length: 3 }, (_, index) =>
          proxy(
            new Request("http://proxy.test/v1/messages?request=" + index, {
              method: "POST",
              headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
              body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "hello" }] }),
            }),
          ),
        ),
      )

      expect(responses.map((response) => response.status)).toEqual([200, 200, 200])
      expect(maxActive).toBe(1)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("removes an aborted client request from the review queue", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    let judgeCalls = 0
    let releaseFirst!: () => void
    let markFirstStarted!: () => void
    const firstStarted = new Promise<void>((resolve) => { markFirstStarted = resolve })
    const firstReleased = new Promise<void>((resolve) => { releaseFirst = resolve })
    const judge = startServer(async () => {
      judgeCalls++
      markFirstStarted()
      await firstReleased
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxConcurrent = 1

    try {
      const proxy = createProxy(proxyConfig)
      const first = proxy(
        new Request("http://proxy.test/v1/messages?request=first", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: "{}",
        }),
      )
      await firstStarted

      const controller = new AbortController()
      const second = proxy(
        new Request("http://proxy.test/v1/messages?request=second", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: "{}",
          signal: controller.signal,
        }),
      )
      controller.abort()
      releaseFirst()

      expect((await first).status).toBe(200)
      const secondResponse = await second
      expect(secondResponse.status).toBe(403)
      expect((await secondResponse.json()).error.message).toBe("审查请求已中止")
      expect(judgeCalls).toBe(1)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("bounds review queue latency by the total review timeout", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const judge = startServer(() => Response.json({ content: [{ type: "text", text: "ALLOW" }] }))
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxConcurrent = 1
    proxyConfig.judgeMinIntervalMs = 100
    proxyConfig.judgeTimeoutMs = 20

    try {
      const proxy = createProxy(proxyConfig)
      const responses = await Promise.all(
        [0, 1].map((index) =>
          proxy(
            new Request(`http://proxy.test/v1/messages?queue=${index}`, {
              method: "POST",
              headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
              body: "{}",
            }),
          ),
        ),
      )

      expect(responses[0]?.status).toBe(200)
      expect(responses[1]?.status).toBe(403)
      expect((await responses[1]?.json()).error.message).toBe("审查排队超时")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("rejects a pending review queue that exceeds its byte budget", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const judge = startServer(async () => {
      await new Promise((resolve) => setTimeout(resolve, 30))
      return Response.json({ content: [{ type: "text", text: "ALLOW" }] })
    })
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), serverPort(upstream))
    proxyConfig.judgeMaxConcurrent = 1
    proxyConfig.judgeQueueBytes = 1

    try {
      const proxy = createProxy(proxyConfig)
      const responses = await Promise.all(
        [0, 1].map((index) =>
          proxy(
            new Request(`http://proxy.test/v1/messages?bytes=${index}`, {
              method: "POST",
              headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
              body: "{}",
            }),
          ),
        ),
      )

      expect(responses[0]?.status).toBe(200)
      expect(responses[1]?.status).toBe(403)
      expect((await responses[1]?.json()).error.message).toBe("审查队列已满")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("forwards without a review model when REVIEW_MODE is off", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    const upstream = startServer(() => Response.json({ forwarded: true }))
    const proxyConfig = config(auditPath, 1, serverPort(upstream))
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: "hello" }] }),
        }),
      )

      expect(response.status).toBe(200)
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line))
      expect(records[0].reason).toBe("审查已关闭")
      expect(records[0].outcome).toBe("skipped")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("uses the active CCSwitch settings for each upstream request", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-test-"))
    const settingsPath = join(auditDir, "settings.json")
    const upstream = startServer((request) => {
      expect(request.headers.get("authorization")).toMatch(/^Bearer /)
      expect(request.headers.get("x-api-key")).toBeNull()
      return Response.json({ forwarded: true })
    })
    await Bun.write(
      settingsPath,
      JSON.stringify({
        env: {
          ANTHROPIC_BASE_URL: `http://127.0.0.1:${serverPort(upstream)}`,
          ANTHROPIC_AUTH_TOKEN: "ccswitch-token",
        },
      }),
    )
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, 1)
    proxyConfig.upstreamSource = "ccswitch"
    proxyConfig.ccswitchSettingsPath = settingsPath
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku", messages: [] }),
        }),
      )

      expect(response.status).toBe(200)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("routes Codex requests to its own upstream and preserves upstream authorization", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-codex-route-test-"))
    let claudeCalls = 0
    let codexCalls = 0
    const claudeUpstream = startServer(() => {
      claudeCalls++
      return Response.json({ wrong: true })
    })
    const codexUpstream = startServer((request) => {
      codexCalls++
      const url = new URL(request.url)
      expect(url.pathname).toBe("/v1/responses")
      expect(url.searchParams.get("api-version")).toBe("2026-08-21")
      expect(url.searchParams.get("stream")).toBe("true")
      expect(request.headers.get("authorization")).toBe("Bearer upstream-codex-token")
      expect(request.headers.get("x-zero-domain-key")).toBeNull()
      return Response.json({ routed: "codex" })
    })
    const proxyConfig = config(
      join(auditDir, "audit.jsonl"),
      1,
      serverPort(claudeUpstream),
    )
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false
    proxyConfig.codexProxyAPIKey = "codex-local-key"
    proxyConfig.codexUpstreamURL = `http://127.0.0.1:${serverPort(codexUpstream)}/v1?api-version=2026-08-21`

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/codex/responses?stream=true", {
          method: "POST",
          headers: {
            authorization: "Bearer upstream-codex-token",
            "content-type": "application/json",
            "x-zero-domain-key": "codex-local-key",
          },
          body: JSON.stringify({ model: "codex-model", input: "hello" }),
        }),
      )

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({ routed: "codex" })
      expect(codexCalls).toBe(1)
      expect(claudeCalls).toBe(0)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("reviews the Codex compact endpoint in api scope", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-codex-compact-test-"))
    let judgeCalls = 0
    let upstreamCalls = 0
    const judge = startServer(() => {
      judgeCalls++
      return Response.json({ content: [{ type: "text", text: "BLOCK: compact blocked" }] })
    })
    const upstream = startServer(() => {
      upstreamCalls++
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(join(auditDir, "audit.jsonl"), serverPort(judge), 1)
    proxyConfig.reviewScope = "api"
    proxyConfig.codexProxyAPIKey = "codex-local-key"
    proxyConfig.codexUpstreamURL = `http://127.0.0.1:${serverPort(upstream)}`

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/codex/responses/compact", {
          method: "POST",
          headers: {
            authorization: "Bearer upstream-codex-token",
            "content-type": "application/json",
            "x-zero-domain-key": "codex-local-key",
          },
          body: JSON.stringify({ model: "codex-model", input: "hello" }),
        }),
      )

      expect(response.status).toBe(403)
      expect(judgeCalls).toBe(1)
      expect(upstreamCalls).toBe(0)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("accepts a distinct Claude proxy key and never forwards it", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-claude-key-test-"))
    const upstream = startServer((request) => {
      expect(request.headers.get("authorization")).toBeNull()
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, serverPort(upstream))
    proxyConfig.reviewMode = "off"
    proxyConfig.judgeEnabled = false
    proxyConfig.upstreamAuthMode = "preserve"
    proxyConfig.claudeProxyAPIKey = "claude-local-key"

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/v1/messages", {
          method: "POST",
          headers: { authorization: "Bearer claude-local-key", "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-model", messages: [] }),
        }),
      )
      expect(response.status).toBe(200)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("does not accept the Claude-only key on the Codex route", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-codex-auth-test-"))
    let upstreamCalls = 0
    const upstream = startServer(() => {
      upstreamCalls++
      return Response.json({ forwarded: true })
    })
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, 1)
    proxyConfig.reviewMode = "off"
    proxyConfig.proxyAPIKey = "master-key"
    proxyConfig.claudeProxyAPIKey = "claude-only-key"
    proxyConfig.codexProxyAPIKey = "codex-only-key"
    proxyConfig.codexUpstreamURL = `http://127.0.0.1:${serverPort(upstream)}`

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/codex/responses", {
          method: "POST",
          headers: { authorization: "Bearer claude-only-key", "content-type": "application/json" },
          body: "{}",
        }),
      )
      expect(response.status).toBe(401)
      expect(upstreamCalls).toBe(0)
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("blocks a Codex upstream that is changed to point back to the proxy", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-codex-loop-test-"))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, 1)
    proxyConfig.reviewMode = "off"
    proxyConfig.codexUpstreamURL = "http://127.0.0.1:0/codex"

    try {
      const response = await createProxy(proxyConfig)(
        new Request("http://proxy.test/codex/responses", {
          method: "POST",
          headers: { authorization: "Bearer proxy-key", "content-type": "application/json" },
          body: "{}",
        }),
      )
      expect(response.status).toBe(502)
      expect((await response.json()).error.message).toBe("Codex upstream points to this proxy")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("loads a fail-closed Anthropic proxy configuration", () => {
    const config = loadConfig({
      UPSTREAM_URL: "https://api.anthropic.com",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
    })
    expect(config.upstreamAuthMode).toBe("anthropic")
    expect(config.upstreamSource).toBe("static")
    expect(config.auditStdout).toBe("off")
    expect(config.reviewMode).toBe("llm")
    expect(config.reviewScope).toBe("all")
    expect(config.judgeProvider).toBe("anthropic")
    expect(config.judgeFailOpen).toBe(false)
  })

  test("uses the supplied environment for default settings paths and rejects non-HTTP upstreams", () => {
    const config = loadConfig({
      HOME: "/tmp/referee-home",
      UPSTREAM_URL: "https://api.anthropic.com",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
    })
    expect(config.ccswitchSettingsPath).toBe("/tmp/referee-home/.claude/settings.json")
    expect(config.claudeSettingsPath).toBe("/tmp/referee-home/.claude/settings.json")
    expect(config.codexConfigPath).toBe("/tmp/referee-home/.codex/config.toml")
    expect(config.codexSettingsAuto).toBe(false)
    expect(config.codexUpstreamURL).toBeUndefined()
    expect(config.codexUpstreamExplicit).toBe(false)
    expect(() => loadConfig({
      UPSTREAM_URL: "file:///tmp/upstream",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
    })).toThrow("UPSTREAM_URL must be an absolute http(s) URL")
    expect(() => loadConfig({
      UPSTREAM_URL: "https://api.anthropic.com",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
      CODEX_PROXY_URL: "http://127.0.0.1:8787/not-codex",
    })).toThrow("CODEX_PROXY_URL path must start with /codex")
    expect(() => loadConfig({
      LISTEN_HOST: "127.0.0.1",
      LISTEN_PORT: "8787",
      UPSTREAM_URL: "https://api.anthropic.com",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
      CODEX_UPSTREAM_URL: "http://localhost:8787/codex",
    })).toThrow("CODEX_UPSTREAM_URL must not point to this proxy")
  })

  test("requires proxy and audit credentials in environment configuration", () => {
    expect(() => loadConfig({ UPSTREAM_URL: "https://api.anthropic.com" })).toThrow("PROXY_API_KEY is required")
  })

  test("prefers REVIEW_* settings and supports disabling model review", () => {
    const config = loadConfig({
      UPSTREAM_URL: "https://relay.example.test",
      PROXY_API_KEY: "proxy-key",
      PROXY_ADMIN_TOKEN: "admin-key",
      JUDGE_ENABLED: "true",
      JUDGE_PROVIDER: "openai-chat",
      JUDGE_MODEL: "legacy-model",
      REVIEW_MODE: "off",
      REVIEW_PROVIDER: "codex",
      REVIEW_MODEL: "review-model",
      REVIEW_TIMEOUT_MS: "1234",
      REVIEW_MAX_OUTPUT_TOKENS: "64",
      REVIEW_MAX_INPUT_CHARS: "4096",
      REVIEW_MAX_MESSAGES: "4",
      REVIEW_SCOPE: "api",
      REVIEW_MAX_CONCURRENT: "3",
      REVIEW_MIN_INTERVAL_MS: "17",
      REVIEW_QUEUE_SIZE: "9",
      REVIEW_QUEUE_BYTES: "12345",
      REVIEW_MAX_RETRIES: "1",
      REVIEW_RETRY_BASE_MS: "11",
      REVIEW_FAIL_OPEN: "true",
      AUDIT_STDOUT: "blocked",
    })

    expect(config.reviewMode).toBe("off")
    expect(config.judgeEnabled).toBe(false)
    expect(config.judgeProvider).toBe("codex")
    expect(config.judgeModel).toBe("review-model")
    expect(config.judgeTimeoutMs).toBe(1234)
    expect(config.judgeMaxOutputTokens).toBe(64)
    expect(config.judgeMaxInputChars).toBe(4096)
    expect(config.judgeMaxMessages).toBe(4)
    expect(config.reviewScope).toBe("api")
    expect(config.judgeMaxConcurrent).toBe(3)
    expect(config.judgeMinIntervalMs).toBe(17)
    expect(config.judgeQueueSize).toBe(9)
    expect(config.judgeQueueBytes).toBe(12345)
    expect(config.judgeMaxRetries).toBe(1)
    expect(config.judgeRetryBaseMs).toBe(11)
    expect(config.judgeFailOpen).toBe(true)
    expect(config.auditStdout).toBe("blocked")
  })

  test("serves an unauthenticated health check without touching the upstream", async () => {
    const proxy = createProxy(config("unused", 1, 1))
    const response = await proxy(new Request("http://proxy.test/healthz"))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true })
  })

  test("serves the admin page and protects the management API", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-admin-test-"))
    const proxyConfig = config(join(auditDir, "audit.jsonl"), 1, 1)
    proxyConfig.adminConfigPath = join(auditDir, "config.json")
    const proxy = createProxy(proxyConfig)

    try {
      const page = await proxy(new Request("http://proxy.test/admin"))
      expect(page.status).toBe(200)
      expect(page.headers.get("cache-control")).toBe("no-store")
      const pageText = await page.text()
      expect(pageText).toContain("零域安全网关控制台")
      expect(pageText).toContain("零域")

      const pageWithSlash = await proxy(new Request("http://proxy.test/admin/"))
      expect(pageWithSlash.status).toBe(200)

      const unauthorized = await proxy(new Request("http://proxy.test/admin/api/config"))
      expect(unauthorized.status).toBe(401)

      const authorized = await proxy(
        new Request("http://proxy.test/admin/api/config", {
          headers: { authorization: "Bearer admin-key" },
        }),
      )
      expect(authorized.status).toBe(200)
      const snapshot = (await authorized.json()) as Record<string, unknown>
      expect(snapshot.reviewScope).toBe("all")
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })

  test("updates runtime config, persists overrides, and filters audit records", async () => {
    const auditDir = await mkdtemp(join(tmpdir(), "zero-domain-admin-test-"))
    const auditPath = join(auditDir, "audit.jsonl")
    const configPath = join(auditDir, "config.json")
    const proxyConfig = config(auditPath, 1, 1)
    proxyConfig.adminConfigPath = configPath
    const proxy = createProxy(proxyConfig)
    await appendFile(
      auditPath,
      `${JSON.stringify({
        id: "admin-log-1",
        time: new Date().toISOString(),
        method: "POST",
        path: "/v1/messages",
        requestBytes: 12,
        bodySHA256: "sample",
        verdict: "block",
        reason: "review required",
        outcome: "blocked",
        durationMs: 8,
      })}\n`,
    )

    try {
      const invalid = await proxy(
        new Request("http://proxy.test/admin/api/config", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ UPSTREAM_URL: "https://changed.example.test", REVIEW_TIMEOUT_MS: "invalid" }),
        }),
      )
      expect(invalid.status).toBe(400)
      expect(proxyConfig.upstreamURL).not.toBe("https://changed.example.test")

      const update = await proxy(
        new Request("http://proxy.test/admin/api/config", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ REVIEW_SCOPE: "api", REVIEW_TIMEOUT_MS: 1234, REVIEW_FAIL_OPEN: true }),
        }),
      )

      expect(update.status).toBe(200)
      expect(proxyConfig.reviewScope).toBe("api")
      expect(proxyConfig.judgeTimeoutMs).toBe(1234)
      expect(proxyConfig.judgeFailOpen).toBe(true)
      expect(JSON.parse(await readFile(configPath, "utf8"))).toMatchObject({
        REVIEW_SCOPE: "api",
        REVIEW_TIMEOUT_MS: "1234",
        REVIEW_FAIL_OPEN: "true",
      })

      const activePort = proxyConfig.listenPort
      const activeClaudeToken = proxyConfig.claudeProxyAPIKey
      const restartUpdate = await proxy(
        new Request("http://proxy.test/admin/api/config", {
          method: "PUT",
          headers: { authorization: "Bearer admin-key", "content-type": "application/json" },
          body: JSON.stringify({ LISTEN_PORT: 9999, CLAUDE_PROXY_API_KEY: "pending-claude-token" }),
        }),
      )
      expect(restartUpdate.status).toBe(200)
      const restartResult = await restartUpdate.json()
      expect(restartResult.restartRequired).toEqual(["LISTEN_PORT", "CLAUDE_PROXY_API_KEY"])
      expect(restartResult.config.runtime.listenPort).toBe(activePort)
      expect(restartResult.config.values.LISTEN_PORT).toBe(9999)
      expect(restartResult.config.pending).toEqual({ LISTEN_PORT: true, CLAUDE_PROXY_API_KEY: true })
      expect(JSON.stringify(restartResult.config)).not.toContain("pending-claude-token")
      expect(proxyConfig.listenPort).toBe(activePort)
      expect(proxyConfig.claudeProxyAPIKey).toBe(activeClaudeToken)

      const logs = await proxy(
        new Request("http://proxy.test/admin/api/audit?path=/v1/messages", {
          headers: { authorization: "Bearer admin-key" },
        }),
      )
      expect(logs.status).toBe(200)
      expect((await logs.json()).records).toHaveLength(1)

      const cleared = await proxy(
        new Request("http://proxy.test/admin/api/audit", {
          method: "DELETE",
          headers: { authorization: "Bearer admin-key" },
        }),
      )
      expect(cleared.status).toBe(200)
      // 2 条配置变更审计 + 1 条消息记录 = 3 条被清除
      expect(await cleared.json()).toEqual({ cleared: 3 })

      const afterClear = await proxy(
        new Request("http://proxy.test/admin/api/audit/stats", {
          headers: { authorization: "Bearer admin-key" },
        }),
      )
      expect(afterClear.status).toBe(200)
      // 删除操作本身追加 1 条审计记录（append-only 轨迹）
      expect(await afterClear.json()).toMatchObject({ total: 1, allow: 1, block: 0 })
    } finally {
      await rm(auditDir, { recursive: true, force: true })
    }
  })
})

function startServer(fetch: (request: Request) => Response | Promise<Response>) {
  const server = Bun.serve({ port: 0, fetch })
  servers.push(server)
  return server
}

function serverPort(server: { port?: number }) {
  if (server.port === undefined) throw new Error("test server did not bind a port")
  return server.port
}

function config(auditPath: string, judgePort: number, upstreamPort: number): ProxyConfig {
  return {
    listenHost: "127.0.0.1",
    listenPort: 0,
    upstreamURL: `http://127.0.0.1:${upstreamPort}`,
    upstreamAPIKey: "upstream-key",
    upstreamAuthMode: "bearer",
    upstreamSource: "static",
    ccswitchSettingsPath: "unused",
    claudeSettingsAuto: false,
    claudeSettingsPath: "unused",
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
    reviewMode: "llm",
    reviewScope: "all",
    judgeEnabled: true,
    judgeProvider: "anthropic",
    judgeBaseURL: `http://127.0.0.1:${judgePort}`,
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
    auditPath,
    auditIncludeBody: "off",
    auditStdout: "off",
  }
}
