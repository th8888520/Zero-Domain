/**
 * 零域管理界面 API + 静态资源托管
 * 页面资源位于 src/admin/static/
 */

import type { ProxyConfig } from "./config"
import {
  appendAudit,
  readAllAudit,
  readAuditPage,
  rewriteAudit,
  stats as computeAuditStats,
  type AuditRecord as StoredAuditRecord,
} from "./audit"
import { resolveUpstream, invalidateUpstreamCache } from "./upstream"
import { writeFile as writeFileAsync, readFile as readFileAsync, copyFile, rename } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const ADMIN_STATIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "admin", "static")

export function adminPage() {
  return new Response(Bun.file(join(ADMIN_STATIC_DIR, "index.html")), {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  })
}

function adminStaticResponse(name: string) {
  if (name !== "admin.css" && name !== "admin.js" && name !== "index.html") {
    return json({ error: "Not Found" }, 404)
  }
  const type =
    name.endsWith(".css") ? "text/css; charset=utf-8" :
    name.endsWith(".js") ? "text/javascript; charset=utf-8" :
    "text/html; charset=utf-8"
  return new Response(Bun.file(join(ADMIN_STATIC_DIR, name)), {
    headers: { "content-type": type, "cache-control": "no-store" },
  })
}

export async function handleAdminAPI(request: Request, url: URL, config: ProxyConfig): Promise<Response | undefined> {
  // 管理页面入口（无需认证）
  if (url.pathname === "/admin" || url.pathname === "/admin/") {
    if (request.method !== "GET") return json({ error: "请求方法不允许" }, 405)
    return adminPage()
  }

  // 静态资源（CSS/JS）
  if (url.pathname.startsWith("/admin/static/")) {
    if (request.method !== "GET" && request.method !== "HEAD") return json({ error: "请求方法不允许" }, 405)
    const name = url.pathname.slice("/admin/static/".length)
    return adminStaticResponse(name)
  }

  // API 端点需要认证
  if (!url.pathname.startsWith("/admin/api/")) return undefined

  const token = config.adminToken
  if (!hasAdminAuth(request, token)) return json({ error: "Unauthorized" }, 401)

  const path = url.pathname
  if (path === "/admin/api/audit" && request.method === "GET") {
    const filterPath = url.searchParams.get("path")
    const verdict = url.searchParams.get("verdict") ?? undefined
    const includeBody = url.searchParams.get("includeBody") === "1"
    const limit = Number(url.searchParams.get("limit") ?? "100")
    const offset = Number(url.searchParams.get("offset") ?? "0")
    const id = url.searchParams.get("id")

    // 单条详情：按需返回含 requestBody 的完整视图
    if (id) {
      const all = await readAllAudit(config.auditPath)
      const hit = all.find((r) => r.id === id)
      if (!hit) return json({ error: "Not Found" }, 404)
      return json({ record: forAdminAuditView(hit, true) })
    }

    if (filterPath) {
      const all = await readAllAudit(config.auditPath)
      const records = all.filter((r) => r.path === filterPath).reverse()
      return json({
        records: records.map((r) => forAdminAuditView(r, includeBody)),
        total: records.length,
        offset: 0,
        limit: records.length,
        hasMore: false,
      })
    }

    const page = await readAuditPage(config.auditPath, {
      limit: Number.isFinite(limit) ? limit : 100,
      offset: Number.isFinite(offset) ? offset : 0,
      verdict,
    })
    return json({
      ...page,
      records: page.records.map((r) => forAdminAuditView(r, includeBody)),
    })
  }
  if (path === "/admin/api/audit" && request.method === "DELETE") {
    const filterPath = url.searchParams.get("path")
    const result = await rewriteAudit(config.auditPath, (records) => {
      if (!filterPath) return []
      return records.filter((r) => r.path !== filterPath)
    })

    await appendAudit(config.auditPath, {
      id: crypto.randomUUID(),
      time: new Date().toISOString(),
      method: "DELETE",
      path: "/admin/api/audit",
      requestBytes: 0,
      bodySHA256: "",
      verdict: "allow",
      reason: `审计记录删除: filter=${filterPath ?? "(all)"}, cleared=${result.cleared}, remaining=${result.after}`,
      outcome: "forwarded",
      durationMs: 0,
    })

    return json({ cleared: result.cleared })
  }
  if (path === "/admin/api/audit/stats") {
    const records = await readAllAudit(config.auditPath)
    return json(computeAuditStats(records))
  }
  if (path === "/admin/api/config" && request.method === "GET") {
    const liveUpstream = await resolveUpstream(config)
    const { buildSecretsReminder, DEFAULT_ADMIN_CONFIG_PATH } = await import("./config-store")
    const configPath = config.adminConfigPath ?? DEFAULT_ADMIN_CONFIG_PATH
    const secretsReminder = await buildSecretsReminder(configPath, [
      {
        key: "REVIEW_API_KEY",
        configured: Boolean(config.judgeAPIKey),
        suffix: secretSuffix(config.judgeAPIKey),
      },
      {
        key: "PROXY_ADMIN_TOKEN",
        configured: Boolean(config.adminToken),
        suffix: secretSuffix(config.adminToken),
      },
      {
        key: "PROXY_API_KEY",
        configured: Boolean(config.proxyAPIKey),
        suffix: secretSuffix(config.proxyAPIKey),
      },
      {
        key: "UPSTREAM_API_KEY",
        configured: Boolean(config.upstreamAPIKey),
        suffix: secretSuffix(config.upstreamAPIKey),
      },
    ])
    return json({
      listenHost: config.listenHost,
      listenPort: config.listenPort,
      // 兼容旧字段：upstreamURL 改为「实时解析到的上游」
      upstreamURL: liveUpstream.url,
      upstreamSource: config.upstreamSource,
      upstreamResolvedFrom: liveUpstream.resolvedFrom,
      upstreamFallbackURL: config.upstreamURL,
      upstreamAuthMode: liveUpstream.authMode,
      auditPath: config.auditPath,
      auditIncludeBody: config.auditIncludeBody,
      auditStdout: config.auditStdout,
      proxyAuthPassthrough: config.proxyAuthPassthrough,
      reviewMode: config.reviewMode,
      reviewScope: config.reviewScope,
      judgeProvider: config.judgeProvider,
      judgeBaseURL: config.judgeBaseURL,
      judgeModel: config.judgeModel,
      judgeTimeoutMs: config.judgeTimeoutMs,
      judgeMaxConcurrent: config.judgeMaxConcurrent,
      judgeMinIntervalMs: config.judgeMinIntervalMs,
      judgeQueueSize: config.judgeQueueSize,
      judgeFailOpen: config.judgeFailOpen,
      disconnectOnBlock: config.disconnectOnBlock,
      // 不回传密钥原文，只给轮换提醒
      judgeAPIKeyConfigured: Boolean(config.judgeAPIKey),
      judgeAPIKeySuffix: secretSuffix(config.judgeAPIKey),
      secretsReminder,
    })
  }

  if (path === "/admin/api/config" && request.method === "PUT") {
    const body = await request.text()
    let updates: Record<string, unknown>
    try {
      updates = JSON.parse(body) as Record<string, unknown>
    } catch {
      return json({ error: "请求体不是有效的 JSON" }, 400)
    }
    if (!isRecord(updates)) {
      return json({ error: "请求体必须是 JSON 对象" }, 400)
    }

    // 严格白名单验证：每个可配置键都有独立的类型/范围/格式校验，
    // 白名单外的键一律拒绝，防止路径篡改、监听地址暴露、密钥窃取等横向影响。
    const validated: Record<string, string> = {}
    for (const [key, value] of Object.entries(updates)) {
      const rule = CONFIG_KEY_RULES[key]
      if (!rule) {
        return json({ error: `不允许通过管理接口修改的配置项: ${key}` }, 400)
      }
      const error = rule.validate(value)
      if (error) {
        return json({ error: `无效的配置值 ${key}: ${error}` }, 400)
      }
      validated[key] = String(value)
    }

    // 应用配置更新并持久化
    const restartRequired: string[] = []
    const overrides: Record<string, string> = {}

    for (const [key, value] of Object.entries(validated)) {
      overrides[key] = value

      if (key === "REVIEW_SCOPE") {
        config.reviewScope = value as "all" | "api"
      } else if (key === "REVIEW_TIMEOUT_MS" || key === "JUDGE_TIMEOUT_MS") {
        config.judgeTimeoutMs = Number(value)
      } else if (key === "REVIEW_FAIL_OPEN" || key === "JUDGE_FAIL_OPEN") {
        config.judgeFailOpen = value === "true"
      } else if (key === "REVIEW_MIN_INTERVAL_MS" || key === "JUDGE_MIN_INTERVAL_MS") {
        config.judgeMinIntervalMs = Number(value)
      } else if (key === "REVIEW_QUEUE_SIZE" || key === "JUDGE_QUEUE_SIZE") {
        config.judgeQueueSize = Number(value)
      } else if (key === "REVIEW_QUEUE_BYTES" || key === "JUDGE_QUEUE_BYTES") {
        config.judgeQueueBytes = Number(value)
      } else if (key === "REVIEW_MAX_RETRIES" || key === "JUDGE_MAX_RETRIES") {
        config.judgeMaxRetries = Number(value)
      } else if (key === "REVIEW_RETRY_BASE_MS" || key === "JUDGE_RETRY_BASE_MS") {
        config.judgeRetryBaseMs = Number(value)
      } else if (key === "REVIEW_MAX_OUTPUT_TOKENS" || key === "JUDGE_MAX_OUTPUT_TOKENS") {
        config.judgeMaxOutputTokens = Number(value)
      } else if (key === "REVIEW_MAX_INPUT_CHARS") {
        config.judgeMaxInputChars = Number(value)
      } else if (key === "REVIEW_MAX_MESSAGES") {
        config.judgeMaxMessages = Number(value)
      } else if (key === "REVIEW_PROMPT") {
        config.judgePrompt = value
      } else if (key === "UPSTREAM_TIMEOUT_MS") {
        config.upstreamTimeoutMs = Number(value)
      } else if (key === "MAX_REQUEST_BYTES") {
        config.maxRequestBytes = Number(value)
      } else if (
        key === "LISTEN_PORT" ||
        key === "CLAUDE_PROXY_API_KEY" ||
        key === "UPSTREAM_URL" ||
        key === "UPSTREAM_API_KEY" ||
        key === "UPSTREAM_SOURCE" ||
        key === "UPSTREAM_AUTH_MODE" ||
        key === "CODEX_UPSTREAM_URL" ||
        key === "CCSWITCH_SETTINGS_PATH" ||
        key === "PROXY_API_KEY" ||
        key === "PROXY_ADMIN_TOKEN"
      ) {
        restartRequired.push(key)
      } else if (key === "AUDIT_STDOUT") {
        config.auditStdout = value as typeof config.auditStdout
      } else if (key === "AUDIT_INCLUDE_BODY") {
        config.auditIncludeBody = value as typeof config.auditIncludeBody
      } else if (key === "REVIEW_MODE") {
        config.reviewMode = value as typeof config.reviewMode
        config.judgeEnabled = value === "llm"
      } else if (key === "REVIEW_PROVIDER") {
        config.judgeProvider = value as typeof config.judgeProvider
      } else if (key === "REVIEW_MODEL") {
        config.judgeModel = value
      } else if (key === "REVIEW_BASE_URL" || key === "JUDGE_BASE_URL") {
        config.judgeBaseURL = value
        restartRequired.push(key)
      } else if (key === "REVIEW_API_KEY" || key === "JUDGE_API_KEY") {
        config.judgeAPIKey = value
      } else if (key === "REVIEW_MAX_CONCURRENT" || key === "JUDGE_MAX_CONCURRENT") {
        config.judgeMaxConcurrent = Number(value)
      } else if (key === "DISCONNECT_ON_BLOCK") {
        config.disconnectOnBlock = value === "true"
      } else if (key === "PROXY_AUTH_PASSTHROUGH") {
        config.proxyAuthPassthrough = value === "true"
      }
    }

    // 持久化到配置文件（默认与已有 overrides 合并）
    const { writeConfigOverrides, markSecretsRotated, DEFAULT_ADMIN_CONFIG_PATH } = await import("./config-store")
    const configPath = config.adminConfigPath ?? DEFAULT_ADMIN_CONFIG_PATH
    await writeConfigOverrides(configPath, overrides, { merge: true })
    await markSecretsRotated(configPath, Object.keys(overrides))
    invalidateUpstreamCache(config.ccswitchSettingsPath)

    // 配置变更本身写入审计日志（记录变更前后的键与脱敏后的新值）
    await appendAudit(config.auditPath, {
      id: crypto.randomUUID(),
      time: new Date().toISOString(),
      method: "PUT",
      path: "/admin/api/config",
      requestBytes: body.length,
      bodySHA256: "",
      verdict: "allow",
      reason: "管理接口配置变更",
      outcome: "forwarded",
      durationMs: 0,
      requestBody: Object.fromEntries(
        Object.entries(validated).map(([key, value]) => [
          key,
          /KEY|TOKEN|SECRET|PASSWORD/i.test(key) ? "***" : value,
        ]),
      ),
    })

    // 脱敏敏感字段（不返回密钥原文）；展示用原始类型值（白名单校验已通过）
    const sanitizedValues: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(updates)) {
      if (key.includes("KEY") || key.includes("TOKEN") || key.includes("SECRET")) {
        sanitizedValues[key] = typeof value === "string" && value.length > 0 ? "***" : value
      } else {
        sanitizedValues[key] = value
      }
    }

    return json({
      restartRequired: restartRequired.length > 0 ? restartRequired : undefined,
      config: {
        runtime: { listenPort: config.listenPort },
        values: sanitizedValues,
        pending: restartRequired.length > 0 ? Object.fromEntries(restartRequired.map(k => [k, true])) : undefined,
      },
    })
  }

  if (path === "/admin/api/env-file" && request.method === "GET") {
    // 在线编辑 .env：返回文件内容、路径、以及被 config.json 覆盖层遮蔽的键
    const envPath = resolve(process.cwd(), ".env")
    let content = ""
    let exists = true
    try {
      content = await readFileAsync(envPath, "utf8")
    } catch {
      exists = false
    }

    // 计算被持久化覆盖层遮蔽的键（这些键在 .env 中修改不会在重启后生效）
    const { readConfigOverrides, DEFAULT_ADMIN_CONFIG_PATH } = await import("./config-store")
    const overrides = await readConfigOverrides(config.adminConfigPath ?? DEFAULT_ADMIN_CONFIG_PATH)
    const overriddenKeys = Object.keys(overrides).filter((key) =>
      new RegExp(`^${key}\\s*=`, "m").test(content),
    )

    return json({
      path: envPath,
      exists,
      content: redactEnvFileContent(content),
      redacted: true,
      overriddenKeys,
    })
  }

  if (path === "/admin/api/env-file" && request.method === "PUT") {
    // 保存 .env：语法校验 → 危险键拒绝 → 自动备份 → 原子写入 → 审计
    const body = await request.text()
    let payload: Record<string, unknown>
    try {
      payload = JSON.parse(body) as Record<string, unknown>
    } catch {
      return json({ error: "请求体不是有效的 JSON" }, 400)
    }
    if (!isRecord(payload) || typeof payload.content !== "string") {
      return json({ error: "请求体必须包含 content 字符串字段" }, 400)
    }
    const content: string = payload.content

    // 语法校验：只允许空行、# 注释、KEY=VALUE 行；并拒绝危险键
    const lines = content.split("\n")
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.trim()
      if (line === "" || line.startsWith("#")) continue
      const keyMatch = /^([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line)
      if (!keyMatch) {
        return json({ error: `第 ${i + 1} 行语法错误: ${line.slice(0, 60)}（应为 KEY=VALUE、# 注释或空行）` }, 400)
      }
      const key = keyMatch[1]!
      if (ENV_FILE_FORBIDDEN_KEYS.has(key)) {
        return json({ error: `不允许通过 env-file 修改危险配置项: ${key}` }, 400)
      }
      const rawValue = envLineValue(line)
      if (ENV_FILE_NON_EMPTY_KEYS.has(key) && rawValue.length === 0) {
        return json({ error: `${key} 不能为空` }, 400)
      }
      // 拒绝把 GET 脱敏占位符写回磁盘，避免重启后密钥退化为字面量 "***"
      if (ENV_SECRET_KEY.test(key) && isEnvRedactionSentinel(rawValue)) {
        return json(
          {
            error: `${key} 当前是脱敏占位符 ***，不能写回；请保留磁盘原值，或填入真实新密钥后再保存`,
          },
          400,
        )
      }
    }

    const envPath = resolve(process.cwd(), ".env")
    const backupPath = `${envPath}.zero-domain-backup`

    // 自动备份现有文件（保留最近一次）
    try {
      await copyFile(envPath, backupPath)
    } catch {
      // 原文件不存在时无需备份
    }

    // 原子写入：临时文件 + rename，避免并发/中断导致文件损坏
    const tmpPath = `${envPath}.tmp-${process.pid}`
    await writeFileAsync(tmpPath, content, "utf8")
    await rename(tmpPath, envPath)

    // 审计记录（不记录内容本身，只记元数据）
    await appendAudit(config.auditPath, {
      id: crypto.randomUUID(),
      time: new Date().toISOString(),
      method: "PUT",
      path: "/admin/api/env-file",
      requestBytes: content.length,
      bodySHA256: "",
      verdict: "allow",
      reason: `环境配置文件已更新: ${envPath}（备份: ${backupPath}），需重启代理生效`,
      outcome: "forwarded",
      durationMs: 0,
    })

    return json({ saved: true, path: envPath, backupPath, restartRequired: true })
  }

  return undefined
}

const ADMIN_BODY_PREVIEW_LIMIT = 4000

function forAdminAuditView(record: StoredAuditRecord, includeBody = false): StoredAuditRecord {
  if (!includeBody) {
    const { requestBody: _requestBody, ...rest } = record
    return rest
  }
  if (record.requestBody === undefined) return record
  const reason = typeof record.reason === "string" ? record.reason : ""
  return {
    ...record,
    requestBody: truncateAuditBody(record.requestBody, ADMIN_BODY_PREVIEW_LIMIT, reason),
  }
}

function truncateAuditBody(body: unknown, maxLen: number, reason = ""): unknown {
  const focused = preferUserFacingBody(body)
  let text: string
  try {
    text = typeof focused === "string" ? focused : JSON.stringify(focused, null, 2)
  } catch {
    text = String(focused)
  }
  if (text.length <= maxLen) return typeof focused === "string" ? focused : focused

  const anchor = findBodyAnchor(text, reason)
  if (anchor >= 0) {
    const start = Math.max(0, anchor - Math.floor(maxLen / 4))
    const slice = text.slice(start, start + maxLen)
    const prefix = start > 0 ? "...(前文已省略)\n" : ""
    const suffix = start + maxLen < text.length ? "...(已截断)" : ""
    return `${prefix}${slice}${suffix}`
  }

  const headLen = Math.floor(maxLen * 0.65)
  const tailLen = Math.max(0, maxLen - headLen - 32)
  return `${text.slice(0, headLen)}\n...\n${text.slice(-tailLen)}...(已截断)`
}

function preferUserFacingBody(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body
  const record = body as Record<string, unknown>
  if (!Array.isArray(record.messages)) return body

  const messages = record.messages as unknown[]
  const picked = messages.slice(-6)
  return {
    model: record.model,
    messages: picked,
    ...(typeof record.system === "string" ? { system: summarizeText(record.system, 500) } : {}),
  }
}

function summarizeText(text: string, maxLen: number) {
  return text.length > maxLen ? `${text.slice(0, maxLen)}...(已截断)` : text
}

function findBodyAnchor(text: string, reason: string) {
  const quote = /[「『"']([^「」『』"']{2,80})[」』"']/.exec(reason || "")
  if (quote?.[1]) {
    const idx = text.indexOf(quote[1])
    if (idx >= 0) return idx
  }

  const tokens = String(reason || "")
    .split(/[\s,，。；;：:|/\\[\]()<>或及与的了并]+/)
    .map(part => part.trim())
    .filter(part => part.length >= 4)
    .sort((a, b) => b.length - a.length)

  for (const token of tokens) {
    const idx = text.indexOf(token)
    if (idx >= 0) return idx
  }

  for (const pattern of ["rm -rf", "DROP TABLE", "systemctl restart", "TRUNCATE", "kill -9"]) {
    const idx = text.indexOf(pattern)
    if (idx >= 0) return idx
  }
  return -1
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

// ─────────────────────────────────────────────────────────────
// 管理接口可配置键白名单
//
// 设计原则：白名单外的键一律拒绝。特别拒绝以下高风险键：
//  - LISTEN_HOST：改为 0.0.0.0 会把本机代理暴露到网络
//  - AUDIT_PATH / ADMIN_CONFIG_PATH / *_SETTINGS_PATH / *_CONFIG_PATH：
//    路径篡改可导致任意文件覆写/读取
// 每个键独立校验类型、取值范围与 URL scheme。
// ─────────────────────────────────────────────────────────────
interface ConfigKeyRule {
  validate: (value: unknown) => string | null
}

function enumRule(...allowed: string[]): ConfigKeyRule {
  return {
    validate: (value) =>
      typeof value === "string" && allowed.includes(value) ? null : `必须是以下之一: ${allowed.join(", ")}`,
  }
}

function booleanRule(): ConfigKeyRule {
  return {
    validate: (value) =>
      value === true || value === false || value === "true" || value === "false" ? null : "必须是布尔值",
  }
}

function numberRule(min: number, max: number): ConfigKeyRule {
  return {
    validate: (value) => {
      const num = Number(value)
      if (typeof value !== "number" && typeof value !== "string") return "必须是数字"
      if (!Number.isFinite(num) || !Number.isInteger(num)) return "必须是整数"
      if (num < min || num > max) return `必须在 ${min} 到 ${max} 之间`
      return null
    },
  }
}

function urlRule(): ConfigKeyRule {
  return {
    validate: (value) => {
      if (typeof value !== "string" || value.length === 0 || value.length > 2048) return "必须是非空字符串(≤2048)"
      try {
        const parsed = new URL(value)
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "必须是 http(s) URL"
        return null
      } catch {
        return "必须是合法的 URL"
      }
    },
  }
}

function stringRule(maxLength: number, allowEmpty = false): ConfigKeyRule {
  return {
    validate: (value) => {
      if (typeof value !== "string") return "必须是字符串"
      if (!allowEmpty && value.length === 0) return "不能为空"
      if (value.length > maxLength) return `长度不能超过 ${maxLength}`
      return null
    },
  }
}

const CONFIG_KEY_RULES: Record<string, ConfigKeyRule> = {
  // 审查行为（运行时可调）
  REVIEW_MODE: enumRule("off", "llm"),
  REVIEW_SCOPE: enumRule("all", "api"),
  REVIEW_PROVIDER: enumRule("anthropic", "openai-responses", "openai-chat", "codex"),
  REVIEW_MODEL: stringRule(128),
  REVIEW_BASE_URL: urlRule(),
  REVIEW_API_KEY: stringRule(512, false),
  REVIEW_TIMEOUT_MS: numberRule(1000, 60_000),
  REVIEW_FAIL_OPEN: booleanRule(),
  REVIEW_MAX_CONCURRENT: numberRule(1, 32),
  REVIEW_MIN_INTERVAL_MS: numberRule(0, 60_000),
  REVIEW_QUEUE_SIZE: numberRule(1, 1000),
  REVIEW_QUEUE_BYTES: numberRule(1024 * 1024, 1024 * 1024 * 1024),
  REVIEW_MAX_RETRIES: numberRule(0, 10),
  REVIEW_RETRY_BASE_MS: numberRule(0, 10_000),
  REVIEW_MAX_OUTPUT_TOKENS: numberRule(1, 8192),
  REVIEW_MAX_INPUT_CHARS: numberRule(1000, 200_000),
  REVIEW_MAX_MESSAGES: numberRule(1, 100),
  REVIEW_PROMPT: stringRule(4000, true),
  // 旧版 JUDGE_* 别名（与 .env 解析保持一致）
  JUDGE_TIMEOUT_MS: numberRule(1000, 60_000),
  JUDGE_FAIL_OPEN: booleanRule(),
  JUDGE_BASE_URL: urlRule(),
  JUDGE_API_KEY: stringRule(512, false),
  JUDGE_MAX_CONCURRENT: numberRule(1, 32),
  JUDGE_MIN_INTERVAL_MS: numberRule(0, 60_000),
  JUDGE_QUEUE_SIZE: numberRule(1, 1000),
  JUDGE_QUEUE_BYTES: numberRule(1024 * 1024, 1024 * 1024 * 1024),
  JUDGE_MAX_RETRIES: numberRule(0, 10),
  JUDGE_RETRY_BASE_MS: numberRule(0, 10_000),
  JUDGE_MAX_OUTPUT_TOKENS: numberRule(1, 8192),
  // 上游与认证（持久化，重启后生效）
  UPSTREAM_URL: urlRule(),
  UPSTREAM_API_KEY: stringRule(512, true),
  UPSTREAM_AUTH_MODE: enumRule("preserve", "anthropic", "bearer"),
  UPSTREAM_SOURCE: enumRule("static", "ccswitch"),
  UPSTREAM_TIMEOUT_MS: numberRule(1000, 600_000),
  PROXY_AUTH_PASSTHROUGH: booleanRule(),
  PROXY_API_KEY: stringRule(512, false),
  PROXY_ADMIN_TOKEN: stringRule(256, false),
  CLAUDE_PROXY_API_KEY: stringRule(512, false),
  CLAUDE_PROXY_URL: urlRule(),
  CLAUDE_SETTINGS_AUTO: booleanRule(),
  CODEX_PROXY_API_KEY: stringRule(512, false),
  CODEX_PROXY_URL: urlRule(),
  CODEX_SETTINGS_AUTO: booleanRule(),
  CODEX_UPSTREAM_URL: urlRule(),
  // 审计输出
  AUDIT_STDOUT: enumRule("off", "blocked", "all"),
  AUDIT_INCLUDE_BODY: enumRule("off", "blocked", "all"),
  // 拦截行为
  DISCONNECT_ON_BLOCK: booleanRule(),
  MAX_REQUEST_BYTES: numberRule(1024 * 1024, 100 * 1024 * 1024),
  // 需重启生效
  LISTEN_PORT: numberRule(1, 65535),
}

function secretSuffix(value: string | undefined) {
  if (!value || value.length < 4) return undefined
  return value.slice(-4)
}

function timingSafeEqualString(left: string, right: string) {
  const encoder = new TextEncoder()
  const a = encoder.encode(left)
  const b = encoder.encode(right)
  if (a.byteLength !== b.byteLength) {
    crypto.timingSafeEqual(a, a)
    return false
  }
  return crypto.timingSafeEqual(a, b)
}

function hasAdminAuth(request: Request, token: string | undefined) {
  if (!token) return false
  const authorization = request.headers.get("authorization") ?? ""
  const raw = authorization.replace(/^Bearer\s+/i, "")
  return timingSafeEqualString(authorization, token) || timingSafeEqualString(raw, token)
}

/** 禁止通过 env-file 写入的危险键（与 config API 白名单意图对齐） */
const ENV_FILE_FORBIDDEN_KEYS = new Set([
  "LISTEN_HOST",
  "AUDIT_PATH",
  "ADMIN_CONFIG_PATH",
  "CLAUDE_SETTINGS_PATH",
  "CODEX_CONFIG_PATH",
  "CCSWITCH_SETTINGS_PATH",
  "CLAUDE_SETTINGS_AUTO",
  "CODEX_SETTINGS_AUTO",
])

/** 这些密钥写入时不允许空值（空密钥会导致认证旁路或管理面裸奔） */
const ENV_FILE_NON_EMPTY_KEYS = new Set([
  "PROXY_API_KEY",
  "PROXY_ADMIN_TOKEN",
  "CLAUDE_PROXY_API_KEY",
  "CODEX_PROXY_API_KEY",
])

const ENV_SECRET_KEY = /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i
const ENV_REDACTION_SENTINEL = "***"

function redactEnvFileContent(content: string) {
  return content
    .split(/\r?\n/)
    .map((line) => {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line)
      if (!match) return line
      const [, key, value] = match
      if (!ENV_SECRET_KEY.test(key!)) return line
      if (!value || value === '""' || value === "''") return `${key}=`
      return `${key}=${ENV_REDACTION_SENTINEL}`
    })
    .join("\n")
}

function envLineValue(line: string): string {
  const eq = line.indexOf("=")
  if (eq < 0) return ""
  let value = line.slice(eq + 1).trim()
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1)
  }
  return value
}

function isEnvRedactionSentinel(value: string) {
  return value === ENV_REDACTION_SENTINEL
}

function json(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } })
}
