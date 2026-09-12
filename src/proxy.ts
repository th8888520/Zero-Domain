import { isProxyEndpoint, type ProxyConfig } from "./config"
import { handleAdminAPI } from "./admin"
import {
  appendAudit,
  readAllAudit,
  readAudit,
  redactBody,
  redactHeaders,
  redactTarget,
  reviewTarget,
  sha256,
  stats,
  type AuditRecord,
} from "./audit"
import { createJudgeScheduler } from "./judge"
import { restore, StreamRestorer, cleanupMapping, getMappingCount } from "./sanitizer"
import { smartSanitize } from "./json-sanitizer"
import { resolveUpstream } from "./upstream"

const JUDGED_PATHS = new Set([
  "/messages",
  "/v1/messages",
  "/responses",
  "/v1/responses",
  "/responses/compact",
  "/v1/responses/compact",
  "/v1/chat/completions",
])
const CODEX_PATH_PREFIX = "/codex"
const CODEX_PROXY_AUTH_HEADER = "x-zero-domain-key"
const DEFAULT_CODEX_UPSTREAM_URL = "https://api.openai.com/v1"
const HOP_BY_HOP_HEADERS = [
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]

export function createProxy(config: ProxyConfig) {
  const judgeScheduler = createJudgeScheduler(config)

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (request.method === "GET" && (url.pathname === "/healthz" || url.pathname === "/health")) return json({ ok: true })
    if (request.method === "GET" && url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204, headers: { "cache-control": "no-store" } })
    }
    if ((request.method === "GET" || request.method === "HEAD") && url.pathname === "/") {
      return Response.redirect(new URL("/admin", url.origin).toString(), 302)
    }
    try {
      const adminResponse = await handleAdminAPI(request, url, config)
      if (adminResponse) return adminResponse
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "admin request failed" }, 400)
    }
    if (url.pathname === "/audit" || url.pathname === "/audit/stats") return handleAudit(request, url, config)

    const id = crypto.randomUUID()
    const started = performance.now()
    const codexRequest = isCodexPath(url.pathname)

    // 透传认证模式：跳过代理认证检查，保留客户端原始 Key
    if (!config.proxyAuthPassthrough && !hasClientProxyAuth(request, config, codexRequest)) {
      await writeAudit(config, {
        id,
        time: new Date().toISOString(),
        method: request.method,
        path: url.pathname,
        requestTarget: redactTarget(url),
        requestBytes: 0,
        bodySHA256: await sha256(new Uint8Array()),
        verdict: "block",
        reason: "代理认证失败",
        outcome: "auth_denied",
        durationMs: elapsed(started),
        requestHeaders: redactHeaders(request.headers),
      })
      return json(
        { error: { type: "authentication_error", message: "代理认证失败", request_id: id } },
        401,
      )
    }

    let bodyBytes: Uint8Array
    try {
      bodyBytes = await readBody(request, config.maxRequestBytes)
    } catch (error) {
      const message = error instanceof Error ? error.message : "请求体过大"
      await writeAudit(
        config,
        baseRecord(id, request, url.pathname, started, {
          requestBytes: 0,
          bodySHA256: await sha256(new Uint8Array()),
          requestTarget: redactTarget(url),
          verdict: "block",
          reason: message,
          outcome: "error",
          requestHeaders: redactHeaders(request.headers),
        }),
      )
      return json({ error: { type: "invalid_request_error", message, request_id: id } }, 413)
    }

    // 上行脱敏：将请求体中的敏感信息替换为占位符
    // 使用 JSON-Aware 脱敏器（优先），保证输出永远是合法 JSON
    const originalBodyBytes = bodyBytes
    const originalBodyText = bodyBytes.byteLength > 0 ? new TextDecoder().decode(bodyBytes) : ""
    const originalParsedBody = parseJSON(originalBodyBytes)

    // 智能脱敏：JSON 请求用结构化脱敏，其他用文本脱敏
    const sanitizeResult = smartSanitize(originalBodyBytes, id)

    let reviewText = originalBodyText
    let sanitizedCount = 0
    if (sanitizeResult.hasChanges) {
      const sanitizedBytes = new TextEncoder().encode(sanitizeResult.sanitized)
      const sanitizedParsedBody = parseJSON(sanitizedBytes)
      reviewText = sanitizeResult.sanitized
      sanitizedCount = getMappingCount(id)

      // JSON-Aware 脱敏保证输出合法，但仍检查以防万一
      if (originalParsedBody === undefined || sanitizedParsedBody !== undefined) {
        bodyBytes = sanitizedBytes
      } else {
        // 理论上不应该到这里（JSON-Aware 保证结构），但保留 fail-closed 兜底
        console.error(`[zero-domain] UNEXPECTED: JSON-aware sanitize broke JSON for request ${id}`)
        cleanupMapping(id)
        await writeAudit(
          config,
          baseRecord(id, request, url.pathname, started, {
            requestBytes: originalBodyBytes.byteLength,
            bodySHA256: await sha256(originalBodyBytes),
            verdict: "block",
            reason: "脱敏后 JSON 解析失败（内部错误），已拒绝",
            outcome: "blocked",
            sanitizedCount,
          }),
        )
        return blockedResponse(
          {
            error: {
              type: "invalid_request_error",
              message: "请求处理内部错误（脱敏失败），请重试或联系管理员",
              request_id: id,
            },
          },
          config,
        )
      }
    }

    const bodySHA256 = await sha256(bodyBytes)
    const parsedBody = parseJSON(bodyBytes)
    // 审查优先使用脱敏文本；可解析则传对象，否则传脱敏原文给审查模型
    const reviewParsed = reviewText ? parseJSON(new TextEncoder().encode(reviewText)) : undefined
    const reviewBody = reviewParsed ?? (reviewText || undefined)
    const model = extractModel(originalParsedBody ?? parsedBody)
    // 与 writeAudit 持久化语义对齐：blocked/all 都要能构造 requestBody
    const shouldIncludeBody =
      config.auditIncludeBody === "all" ||
      config.auditIncludeBody === "blocked" ||
      config.auditStdout === "all"
    const requestBody = shouldIncludeBody
      ? redactBody(parsedBody ?? new TextDecoder().decode(bodyBytes))
      : undefined
    const common = {
      requestBytes: bodyBytes.byteLength,
      bodySHA256,
      model,
      sanitizedCount,
      authMode: config.proxyAuthPassthrough ? "passthrough" : "proxy",
      requestTarget: redactTarget(url),
      requestHeaders: redactHeaders(request.headers),
      ...(requestBody === undefined ? {} : { requestBody }),
    }

    const apiPath = codexRequest ? stripCodexPrefix(url.pathname) : url.pathname
    if (shouldJudge(request.method, apiPath, config.reviewScope)) {
      if (config.reviewScope === "api" && bodyBytes.byteLength > 0 && !parsedBody) {
        if (sanitizeResult.hasChanges) cleanupMapping(id)
        await writeAudit(
          config,
          baseRecord(id, request, url.pathname, started, {
            ...common,
            verdict: "block",
            reason: "请求体不是有效的 JSON",
            outcome: "error",
          }),
        )
        return json(
          { error: { type: "invalid_request_error", message: "请求体不是有效的 JSON", request_id: id } },
          400,
        )
      }

      const verdict = await judgeScheduler.run(
        {
          method: request.method,
          path: reviewTarget(url),
          body: reviewBody,
          signal: request.signal,
          sizeBytes: bodyBytes.byteLength,
        },
      )
      if (!verdict.allowed) {
        if (sanitizeResult.hasChanges) cleanupMapping(id)
        await writeAudit(
          config,
          baseRecord(id, request, url.pathname, started, {
            ...common,
            verdict: "block",
            reason: verdict.reason,
            outcome: verdict.outcome === "error" ? "error" : "blocked",
            judgeProvider: config.judgeProvider,
            judgeModel: config.judgeModel,
            judgeRaw: verdict.raw,
            judgeStatus: verdict.status,
            judgeErrorKind: verdict.errorKind,
            judgeAttempts: verdict.attempts,
            judgeQueueWaitMs: verdict.queueWaitMs,
            judgeReviewEscalated: verdict.reviewEscalated,
            durationMs: elapsed(started),
          }),
        )
        return blockedResponse({ error: { type: "request_blocked", message: verdict.reason, request_id: id } }, config)
      }

      const forwarded = await forward(request, url, bodyBytes, config)
      await writeAudit(
        config,
        baseRecord(id, request, url.pathname, started, {
          ...common,
          verdict: "allow",
          reason: verdict.reason,
          outcome:
            verdict.outcome === "error" || forwarded.failed
              ? "error"
              : verdict.outcome === "skipped"
                ? "skipped"
                : "forwarded",
          judgeProvider: config.judgeProvider,
          judgeModel: config.judgeModel,
          judgeRaw: verdict.raw,
          judgeStatus: verdict.status,
          judgeErrorKind: verdict.errorKind,
          judgeAttempts: verdict.attempts,
          judgeQueueWaitMs: verdict.queueWaitMs,
          judgeReviewEscalated: verdict.reviewEscalated,
          upstreamStatus: forwarded.response.status,
          durationMs: elapsed(started),
        }),
      )
      // 下行还原：将上游响应中的占位符还原为原文
      const restoredResponse = await restoreResponse(forwarded.response, id)
      return addProxyHeaders(restoredResponse, id)
    }

    const forwarded = await forward(request, url, bodyBytes, config)
    await writeAudit(
      config,
      baseRecord(id, request, url.pathname, started, {
        ...common,
        verdict: "allow",
        reason: reviewSkipReason(request.method, config.reviewScope),
        outcome: forwarded.failed ? "error" : "skipped",
        upstreamStatus: forwarded.response.status,
        durationMs: elapsed(started),
      }),
    )
    // 下行还原
    const restoredResponse = await restoreResponse(forwarded.response, id)
    return addProxyHeaders(restoredResponse, id)
  }
}

async function handleAudit(request: Request, url: URL, config: ProxyConfig) {
  if (!hasProxyAuth(request, config.adminToken)) return json({ error: "admin authentication failed" }, 401)
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? "100") || 100, 1), 1_000)
  if (url.pathname === "/audit/stats") return json(stats(await readAllAudit(config.auditPath)))
  const records = await readAudit(config.auditPath, limit)
  return json({ data: records, hasMore: records.length === limit })
}

async function forward(request: Request, url: URL, body: Uint8Array, config: ProxyConfig) {
  const codexRequest = isCodexPath(url.pathname)
  if (codexRequest && config.codexUpstreamURL && isProxyEndpoint(config.codexUpstreamURL, config)) {
    return {
      response: json({ error: { type: "upstream_error", message: "Codex upstream points to this proxy" } }, 502),
      failed: true,
    }
  }
  const upstream = codexRequest
    ? { url: config.codexUpstreamURL ?? DEFAULT_CODEX_UPSTREAM_URL, authMode: "preserve" as const }
    : await resolveUpstream(config)
  const headers = forwardHeaders(request.headers, config, upstream)
  const forwardedURL = new URL(url)
  if (codexRequest) forwardedURL.pathname = stripCodexPrefix(url.pathname)
  try {
    const response = await fetchWithHeaderTimeout(upstreamURL(forwardedURL, upstream.url), {
      method: request.method,
      headers,
      body: body.byteLength > 0 && request.method !== "GET" && request.method !== "HEAD" ? body : undefined,
    }, request.signal, config.upstreamTimeoutMs)
    return { response, failed: false }
  } catch {
    return {
      response: json({ error: { type: "upstream_error", message: "upstream request failed" } }, 502),
      failed: true,
    }
  }
}

async function fetchWithHeaderTimeout(
  input: RequestInfo | URL,
  init: RequestInit,
  requestSignal: AbortSignal,
  timeoutMs: number,
) {
  const timeoutController = new AbortController()
  const timer = setTimeout(
    () => timeoutController.abort(new DOMException("upstream connection timed out", "TimeoutError")),
    timeoutMs,
  )
  try {
    return await fetch(input, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.any([requestSignal, timeoutController.signal]),
    })
  } catch (error) {
    // 记录超时和网络错误，帮助诊断上游问题
    if (error instanceof Error) {
      if (error.name === "AbortError" || error.name === "TimeoutError") {
        console.warn(`[zero-domain] upstream timeout: ${input instanceof URL ? input.href : String(input)}`)
      } else if (error.message.includes("fetch")) {
        console.warn(`[zero-domain] upstream connection failed: ${error.message}`)
      }
    }
    throw error
  } finally {
    clearTimeout(timer)
  }
}

function forwardHeaders(
  source: Headers,
  config: ProxyConfig,
  upstream: { apiKey?: string; authMode: ProxyConfig["upstreamAuthMode"] },
) {
  const headers = new Headers(source)
  for (const name of HOP_BY_HOP_HEADERS) headers.delete(name)
  const connectionTokens = source
    .get("connection")
    ?.split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
  for (const name of connectionTokens ?? []) headers.delete(name)
  headers.delete(CODEX_PROXY_AUTH_HEADER)

  // 透传认证模式：保留客户端原始凭证，不删除也不替换，也不得注入配置里的上游 Key
  if (!config.proxyAuthPassthrough) {
    removeProxyCredentials(headers, [config.proxyAPIKey, config.claudeProxyAPIKey, config.codexProxyAPIKey])
  }

  if (!config.proxyAuthPassthrough && upstream.apiKey && upstream.authMode !== "preserve") {
    headers.delete("authorization")
    headers.delete("x-api-key")
    if (upstream.authMode === "anthropic") headers.set("x-api-key", upstream.apiKey)
    if (upstream.authMode === "bearer") headers.set("authorization", `Bearer ${upstream.apiKey}`)
  }
  return headers
}

function upstreamURL(requestURL: URL, upstreamBase: string) {
  const base = new URL(upstreamBase)
  const basePath = base.pathname.replace(/\/+$/, "")
  const incomingPath = requestURL.pathname
  base.pathname =
    incomingPath === basePath || incomingPath.startsWith(`${basePath}/`) ? incomingPath : `${basePath}${incomingPath}`
  const baseQuery = base.search.replace(/^\?/, "")
  const incomingQuery = requestURL.search.replace(/^\?/, "")
  base.search = [baseQuery, incomingQuery].filter(Boolean).join("&")
  return base
}

function removeProxyCredentials(headers: Headers, proxyAPIKeys: Array<string | undefined>) {
  const authorization = headers.get("authorization")
  const apiKey = headers.get("x-api-key")
  const authorizationValue = authorization?.replace(/^Bearer\s+/i, "")
  if (proxyAPIKeys.some((value) => value && authorizationValue === value)) headers.delete("authorization")
  if (proxyAPIKeys.some((value) => value && apiKey === value)) headers.delete("x-api-key")
}

function isCodexPath(pathname: string) {
  return pathname === CODEX_PATH_PREFIX || pathname.startsWith(`${CODEX_PATH_PREFIX}/`)
}

function stripCodexPrefix(pathname: string) {
  const stripped = pathname.slice(CODEX_PATH_PREFIX.length)
  return stripped || "/"
}

async function readBody(request: Request, maxBytes: number) {
  const declared = Number(request.headers.get("content-length") ?? "0")
  if (declared > maxBytes) throw new Error(`请求体超过 ${maxBytes} 字节上限`)
  if (!request.body) return new Uint8Array()

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
      total += chunk.byteLength
      if (total > maxBytes) {
        try {
          await reader.cancel()
        } catch {
          // Preserve the size error when the client stream is already closed.
        }
        throw new Error(`请求体超过 ${maxBytes} 字节上限`)
      }
      chunks.push(chunk)
    }
  } finally {
    reader.releaseLock()
  }

  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

function shouldJudge(method: string, path: string, scope: ProxyConfig["reviewScope"]) {
  if (method.toUpperCase() === "OPTIONS") return false
  if (scope === "all") return true
  return JUDGED_PATHS.has(path.replace(/\/$/, ""))
}

function reviewSkipReason(method: string, scope: ProxyConfig["reviewScope"]) {
  if (method.toUpperCase() === "OPTIONS") return "OPTIONS 请求不参与审查"
  return scope === "api" ? "该路径未配置审查" : "请求未纳入审查"
}

function extractModel(body: unknown) {
  return isRecord(body) && typeof body.model === "string" ? body.model : undefined
}

function parseJSON(bytes: Uint8Array) {
  if (bytes.byteLength === 0) return undefined
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown
  } catch {
    return undefined
  }
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

function hasProxyAuth(request: Request, expected: string | undefined) {
  if (!expected) return false
  const authorization = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? ""
  const apiKey = request.headers.get("x-api-key") ?? ""
  return timingSafeEqualString(authorization, expected) || timingSafeEqualString(apiKey, expected)
}

function hasClientProxyAuth(request: Request, config: ProxyConfig, codexRequest: boolean) {
  if (hasProxyAuth(request, config.proxyAPIKey)) return true
  if (codexRequest) {
    if (hasProxyAuth(request, config.codexProxyAPIKey)) return true
    const header = request.headers.get(CODEX_PROXY_AUTH_HEADER) ?? ""
    return Boolean(config.codexProxyAPIKey) && timingSafeEqualString(header, config.codexProxyAPIKey!)
  }
  return hasProxyAuth(request, config.claudeProxyAPIKey)
}

function addProxyHeaders(response: Response, id: string) {
  const headers = new Headers(response.headers)
  headers.set("x-zero-domain-request-id", id)
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

function baseRecord(
  id: string,
  request: Request,
  path: string,
  started: number,
  record: Partial<AuditRecord>,
): AuditRecord {
  return {
    id,
    time: new Date().toISOString(),
    method: request.method,
    path,
    requestBytes: 0,
    bodySHA256: "",
    verdict: "allow",
    reason: "",
    outcome: "error",
    durationMs: elapsed(started),
    ...record,
  }
}

async function writeAudit(config: ProxyConfig, record: AuditRecord) {
  printAudit(config, record)
  // 根据配置决定是否持久化请求体：
  // - "all": 总是保存
  // - "blocked": 仅保存被拦截的请求
  // - "off": 不保存
  const shouldPersistBody =
    config.auditIncludeBody === "all" ||
    (config.auditIncludeBody === "blocked" && record.verdict === "block")
  const persistedRecord = shouldPersistBody ? record : withoutRequestBody(record)
  try {
    await appendAudit(config.auditPath, persistedRecord)
  } catch (error) {
    console.error(`[zero-domain] audit write failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function printAudit(config: ProxyConfig, record: AuditRecord) {
  if (config.auditStdout === "off") return
  if (config.auditStdout === "blocked" && record.verdict !== "block") return

  const summary =
    record.verdict === "block"
      ? {
          判定: "拦截",
          原因: record.reason,
          结果: auditOutcomeLabel(record.outcome),
          审查模型: record.judgeModel ?? "",
          审查尝试次数: record.judgeAttempts ?? 0,
          审查排队毫秒: record.judgeQueueWaitMs ?? 0,
          耗时毫秒: record.durationMs,
        }
      : {
          时间: record.time,
          请求ID: record.id,
          方法: record.method,
          接口: record.path,
          目标: record.requestTarget,
          模型: record.model,
          请求体: record.requestBody,
          判定: "通过",
          原因: record.reason,
          结果: auditOutcomeLabel(record.outcome),
          审查提供方: record.judgeProvider,
          审查模型: record.judgeModel,
          审查状态: record.judgeStatus,
          审查错误类型: record.judgeErrorKind,
          审查尝试次数: record.judgeAttempts,
          审查排队毫秒: record.judgeQueueWaitMs,
          上游状态: record.upstreamStatus,
          耗时毫秒: record.durationMs,
        }
  console.log(JSON.stringify(summary))
}

function withoutRequestBody(record: AuditRecord): AuditRecord {
  const { requestBody: _requestBody, ...rest } = record
  return rest
}

function auditOutcomeLabel(outcome: AuditRecord["outcome"]) {
  if (outcome === "forwarded") return "已转发"
  if (outcome === "blocked") return "已拦截"
  if (outcome === "error") return "错误"
  if (outcome === "skipped") return "已跳过"
  return "认证拒绝"
}

function elapsed(started: number) {
  return Math.round(performance.now() - started)
}

function json(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } })
}

function blockedResponse(value: unknown, config: ProxyConfig) {
  if (config.disconnectOnBlock) {
    return new Response(null, {
      status: 403,
      headers: {
        "cache-control": "no-store",
        connection: "close",
        "content-length": "0",
      },
    })
  }
  return json(value, 403)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/**
 * 下行还原响应：支持 SSE 流式和普通响应
 */
async function restoreResponse(response: Response, mappingId: string): Promise<Response> {
  const contentType = response.headers.get("content-type") || ""
  const isSSE = contentType.includes("text/event-stream")

  // SSE 流式响应：逐块还原
  if (isSSE && response.body) {
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    const encoder = new TextEncoder()
    const restorer = new StreamRestorer(mappingId)

    const stream = new ReadableStream({
      async start(controller) {
        try {
          while (true) {
            const { done, value } = await reader.read()
            if (done) {
              // 输出剩余内容
              const final = restorer.finalize()
              if (final) {
                controller.enqueue(encoder.encode(final))
              }
              break
            }

            // 解码并还原当前块
            const chunk = decoder.decode(value, { stream: true })
            const restored = restorer.process(chunk)

            if (restored) {
              controller.enqueue(encoder.encode(restored))
            }
          }
        } catch (error) {
          controller.error(error)
        } finally {
          controller.close()
          cleanupMapping(mappingId)
        }
      },
      cancel() {
        reader.cancel()
        cleanupMapping(mappingId)
      },
    })

    return new Response(stream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    })
  }

  // 普通响应：一次性还原
  if (!response.body) {
    cleanupMapping(mappingId)
    return response
  }

  try {
    const bodyBytes = new Uint8Array(await response.arrayBuffer())
    const restored = restore(bodyBytes, mappingId)

    return new Response(restored, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    })
  } finally {
    cleanupMapping(mappingId)
  }
}
