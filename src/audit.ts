import { appendFile, mkdir, rename, writeFile } from "node:fs/promises"
import { dirname } from "node:path"

export type AuditVerdict = "allow" | "block"
export type AuditOutcome = "forwarded" | "blocked" | "error" | "skipped" | "auth_denied"

export interface AuditRecord {
  id: string
  time: string
  method: string
  path: string
  model?: string
  requestBytes: number
  bodySHA256: string
  verdict: AuditVerdict
  reason: string
  outcome: AuditOutcome
  judgeProvider?: string
  judgeModel?: string
  judgeRaw?: string
  judgeStatus?: number
  judgeErrorKind?: string
  judgeAttempts?: number
  judgeQueueWaitMs?: number
  judgeReviewEscalated?: boolean
  upstreamStatus?: number
  durationMs: number
  requestTarget?: string
  requestHeaders?: Record<string, string>
  requestBody?: unknown
  sanitizedCount?: number
}

const SENSITIVE_KEY = /(?:authorization|api[-_]?key|token|secret|password|cookie|credential|signature)/i
const HIGH_RISK_QUERY_VALUE =
  /\b(?:drop|truncate|delete|alter|create\s+(?:user|role|account)|grant|revoke|rm|kill|shutdown|reboot|systemctl|service|powershell|cmd(?:\.exe)?|bash|sh|exec|eval|curl|wget)\b/i
const SENSITIVE_ASSIGNMENT =
  /((?:^|[?&;\s])(?:authorization|api[-_]?key|token|secret|password|cookie|credential|signature)\s*[=:]\s*)([^&;\s]+)/gi
const SENSITIVE_HEADER =
  /((?:^|[\r\n])\s*(?:authorization|api[-_]?key|token|secret|password|cookie|credential|signature)\s*:\s*)([^\r\n]+)/gi
const MAX_PREVIEW_STRING = 4_000
const MAX_AUDIT_FILE_SIZE = 100 * 1024 * 1024  // 100MB
const auditWriteQueues = new Map<string, Promise<void>>()

export async function appendAudit(path: string, record: AuditRecord) {
  await enqueueAuditWrite(path, async () => {
    await mkdir(dirname(path), { recursive: true })

    // 检查文件大小，超过阈值则轮转（rename，避免整文件读入内存）
    try {
      const stat = await Bun.file(path).size
      if (stat >= MAX_AUDIT_FILE_SIZE) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)
        const rotatedPath = `${path}.${timestamp}`
        await rename(path, rotatedPath)
        await writeFile(path, "", "utf8")
        console.log(`[zero-domain] audit log rotated: ${rotatedPath}`)
      }
    } catch {
      // 文件不存在或无法读取时忽略，继续追加
    }

    await appendFile(path, `${JSON.stringify(record)}\n`, "utf8")
  })
}

export async function clearAudit(path: string) {
  return enqueueAuditWrite(path, async () => {
    const records = await readAllAuditUnlocked(path)
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, "", "utf8")
    return records.length
  })
}

/** 在写队列内重写审计文件，避免与 appendAudit 竞态 */
export async function rewriteAudit(
  path: string,
  transform: (records: AuditRecord[]) => AuditRecord[] | Promise<AuditRecord[]>,
) {
  return enqueueAuditWrite(path, async () => {
    const records = await readAllAuditUnlocked(path)
    const next = await transform(records)
    await mkdir(dirname(path), { recursive: true })
    const body = next.length > 0 ? `${next.map((r) => JSON.stringify(r)).join("\n")}\n` : ""
    await writeFile(path, body, "utf8")
    return { before: records.length, after: next.length, cleared: records.length - next.length }
  })
}

export async function readAudit(path: string, limit: number) {
  const rows = await readAllAudit(path)
  return rows.slice(-limit).reverse()
}

/** 与写队列串行，避免并发 rewrite 时读到半行 */
export async function readAllAudit(path: string) {
  return enqueueAuditWrite(path, () => readAllAuditUnlocked(path))
}

async function readAllAuditUnlocked(path: string) {
  const content = await readText(path)
  return content
    .split("\n")
    .filter((line) => line.trim())
    .flatMap((line) => parseRecord(line))
}

/** 返回最新在前；可选按 verdict 过滤。避免管理端无脑拉全量。 */
export async function readAuditPage(
  path: string,
  options?: { limit?: number; offset?: number; verdict?: string },
) {
  return enqueueAuditWrite(path, async () => {
    const limit = Math.max(1, Math.min(options?.limit ?? 100, 500))
    const offset = Math.max(0, options?.offset ?? 0)
    const all = await readAllAuditUnlocked(path)
    const filtered = options?.verdict
      ? all.filter((r) => r.verdict === options.verdict)
      : all
    const newestFirst = filtered.slice().reverse()
    const page = newestFirst.slice(offset, offset + limit)
    return {
      records: page,
      total: filtered.length,
      offset,
      limit,
      hasMore: offset + page.length < filtered.length,
    }
  })
}

export function stats(records: readonly AuditRecord[]) {
  return records.reduce(
    (result, record) => {
      result.total++
      if (record.verdict === "allow") result.allow++
      if (record.verdict === "block") result.block++
      if (record.outcome === "error") result.error++
      if (record.outcome === "forwarded") result.forwarded++
      if (record.outcome === "skipped") result.skipped++
      return result
    },
    { total: 0, allow: 0, block: 0, error: 0, forwarded: 0, skipped: 0 },
  )
}

export function redactHeaders(headers: Headers) {
  return Object.fromEntries(
    Array.from(headers.entries()).map(([key, value]) => [key, SENSITIVE_KEY.test(key) ? "[REDACTED]" : value]),
  )
}

export function redactTarget(url: URL) {
  return formatTarget(url, false)
}

export function reviewTarget(url: URL) {
  return formatTarget(url, true)
}

function formatTarget(url: URL, revealHighRiskValues: boolean) {
  const params = new URLSearchParams()
  for (const [key, value] of url.searchParams) {
    const reveal = revealHighRiskValues && HIGH_RISK_QUERY_VALUE.test(value)
    params.append(key, SENSITIVE_KEY.test(key) && !reveal ? "[REDACTED]" : value)
  }
  const query = params.toString()
  return `${url.pathname}${query ? `?${query}` : ""}`
}

export function redactBody(body: unknown): unknown {
  if (typeof body === "string") return redactString(body)
  if (Array.isArray(body)) return body.map((item) => redactBody(item))
  if (!isRecord(body)) return body

  return Object.fromEntries(
    Object.entries(body).map(([key, value]) => [key, SENSITIVE_KEY.test(key) ? "[REDACTED]" : redactBody(value)]),
  )
}

function redactString(value: string) {
  const redacted = value
    .replace(SENSITIVE_ASSIGNMENT, "$1[REDACTED]")
    .replace(SENSITIVE_HEADER, "$1[REDACTED]")
  return redacted.length > MAX_PREVIEW_STRING ? `${redacted.slice(0, MAX_PREVIEW_STRING)}...` : redacted
}

export async function sha256(input: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", input)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function readText(path: string) {
  try {
    return await Bun.file(path).text()
  } catch {
    return ""
  }
}

function parseRecord(line: string) {
  try {
    const value = JSON.parse(line) as unknown
    return isRecord(value) && typeof value.id === "string" ? [value as unknown as AuditRecord] : []
  } catch {
    return []
  }
}

async function enqueueAuditWrite<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const previous = auditWriteQueues.get(path) ?? Promise.resolve()
  const next = previous.then(operation, operation)
  const settled = next.then(() => undefined, () => undefined)
  auditWriteQueues.set(path, settled)
  void settled.then(() => {
    if (auditWriteQueues.get(path) === settled) auditWriteQueues.delete(path)
  })
  return next
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
