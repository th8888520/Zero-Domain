/**
 * 编码内容探测器
 *
 * 审查前置环节：请求中的高危命令可能以 base64 / hex / URL 编码形式发送，
 * 审查模型直接看原文难以识别。本模块自动扫描送审文本中的疑似编码字符串，
 * 解码后以附加上下文形式交给审查模型评估。
 *
 * 仅用于审查投影（judge prompt），不影响实际上行转发的内容。
 */

export interface DecodedFinding {
  kind: "base64" | "hex" | "url"
  encoded: string
  decoded: string
}

// 单个解码结果的最大展示长度与附加上限（防审查输入膨胀）
const MAX_DECODED_LEN = 500
const DEFAULT_MAX_FINDINGS = 10
/** 硬拦扫描：最多检查多少编码候选；超长文本头尾窗口 */
const SECURITY_MAX_CHECKS = 20_000
const SECURITY_MAX_DEPTH = 6
const SECURITY_WINDOW = 100_000

// base64：至少 8 字符、标准字符集、可带 = 填充（宽松边界，减少普通单词误匹配）
const BASE64_CANDIDATE = /[A-Za-z0-9+/]{8,}={0,2}/g
// hex：至少 16 个十六进制字符（8 字节）
const HEX_CANDIDATE = /\b(?:[0-9a-fA-F]{2}){8,}\b/g
// URL 编码：含 %XX 序列的 token（数量校验在解码前单独进行）
const URL_ENCODED_CANDIDATE = /[A-Za-z0-9%._~+-]*%[0-9a-fA-F]{2}[A-Za-z0-9%._~+-]*/g
const URL_SEQ_COUNT = /%[0-9a-fA-F]{2}/g

export type DecodeOptions = {
  /** 最多保留多少条解码结果（展示用默认 10；硬拦用更大） */
  limit?: number
  /** 嵌套解码层数（展示默认 2；硬拦默认 4） */
  maxDepth?: number
}

/**
 * 扫描文本中的疑似编码字符串并尝试解码。
 * 解码结果须为「大部分可打印」的自然文本，否则视为误匹配丢弃。
 */
export function decodeSuspiciousStrings(text: string, options?: DecodeOptions): DecodedFinding[] {
  return decodeInternal(text, {
    limit: options?.limit ?? DEFAULT_MAX_FINDINGS,
    maxDepth: options?.maxDepth ?? 2,
  })
}

/**
 * 本地硬拦专用：对每个编码候选「解码即检」，命中即返回。
 * - 先扫尾部窗口（对抗前缀 padding/decoy）
 * - 同类候选从后往前检
 * - 仅成功解码计入预算（避免 hex 子串耗尽配额）
 */
export function scanEncodedForMatch(
  text: string,
  match: (decoded: string) => string | undefined,
  options?: { maxChecks?: number; maxDepth?: number },
): string | undefined {
  if (!text) return undefined
  const maxChecks = options?.maxChecks ?? SECURITY_MAX_CHECKS
  const maxDepth = options?.maxDepth ?? SECURITY_MAX_DEPTH
  const state = { checks: 0, seen: new Set<string>() }

  if (text.length <= SECURITY_WINDOW) {
    return walkEncoded(text, 0, match, maxChecks, maxDepth, state)
  }
  // 超长：先尾后头，防止前缀填充把恶意串挤出窗口
  return (
    walkEncoded(text.slice(-SECURITY_WINDOW), 0, match, maxChecks, maxDepth, state) ??
    walkEncoded(text.slice(0, SECURITY_WINDOW), 0, match, maxChecks, maxDepth, state)
  )
}

function walkEncoded(
  text: string,
  depth: number,
  match: (decoded: string) => string | undefined,
  maxChecks: number,
  maxDepth: number,
  state: { checks: number; seen: Set<string> },
): string | undefined {
  if (depth > maxDepth || !text) return undefined

  for (const [pattern, kind] of [
    [BASE64_CANDIDATE, "base64"],
    [URL_ENCODED_CANDIDATE, "url"],
    [HEX_CANDIDATE, "hex"],
  ] as const) {
    const encodedList: string[] = []
    pattern.lastIndex = 0
    let matched: RegExpExecArray | null
    while ((matched = pattern.exec(text)) !== null) {
      encodedList.push(matched[0])
    }

    // 从尾部往前，对抗前缀 decoy
    for (let i = encodedList.length - 1; i >= 0; i--) {
      if (state.checks >= maxChecks) return undefined

      const encoded = encodedList[i]!
      const dedupeKey = `${kind}:${encoded}`
      if (state.seen.has(dedupeKey)) continue
      state.seen.add(dedupeKey)

      if (kind === "url" && (encoded.match(URL_SEQ_COUNT)?.length ?? 0) < 2) continue

      const decoded = tryDecode(kind, encoded)
      if (decoded === undefined || decoded === encoded) continue
      state.checks += 1

      const hit = match(decoded)
      if (hit) return hit

      const nested = walkEncoded(decoded, depth + 1, match, maxChecks, maxDepth, state)
      if (nested) return nested
    }
  }
  return undefined
}

function decodeInternal(text: string, options: { limit: number; maxDepth: number }): DecodedFinding[] {
  const findings: DecodedFinding[] = []
  const seen = new Set<string>()
  if (!text) return findings

  let layerTexts = [text]
  for (let depth = 0; depth < options.maxDepth; depth++) {
    const nextLayer: string[] = []
    for (const layerText of layerTexts) {
      const before = findings.length
      collect(layerText, BASE64_CANDIDATE, "base64", findings, seen, options.limit)
      collect(layerText, HEX_CANDIDATE, "hex", findings, seen, options.limit)
      collect(layerText, URL_ENCODED_CANDIDATE, "url", findings, seen, options.limit)
      for (let i = before; i < findings.length; i++) nextLayer.push(findings[i]!.decoded)
      if (findings.length >= options.limit) return findings.slice(0, options.limit)
    }
    layerTexts = nextLayer
    if (layerTexts.length === 0) break
  }

  return findings.slice(0, options.limit)
}

function collect(
  text: string,
  pattern: RegExp,
  kind: DecodedFinding["kind"],
  findings: DecodedFinding[],
  seen: Set<string>,
  limit: number,
) {
  pattern.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    if (findings.length >= limit) return
    const encoded = match[0]

    // 去重：同一编码串只解码一次
    const dedupeKey = `${kind}:${encoded}`
    if (seen.has(dedupeKey)) continue
    seen.add(dedupeKey)

    // URL 类候选须含 ≥2 个 %XX 序列，避免对单个转义字符过度解码
    if (kind === "url" && (encoded.match(URL_SEQ_COUNT)?.length ?? 0) < 2) continue

    const decoded = tryDecode(kind, encoded)
    if (decoded === undefined) continue
    if (decoded === encoded) continue // 解码后无变化（如 url 编码串实际无 %XX）

    findings.push({
      kind,
      encoded: encoded.length > 120 ? `${encoded.slice(0, 117)}...` : encoded,
      decoded: decoded.length > MAX_DECODED_LEN ? `${decoded.slice(0, MAX_DECODED_LEN)}...` : decoded,
    })
  }
}

function tryDecode(kind: DecodedFinding["kind"], encoded: string): string | undefined {
  try {
    if (kind === "base64") return decodeBase64(encoded)
    if (kind === "hex") return decodeHex(encoded)
    return safeDecodeURIComponent(encoded)
  } catch {
    return undefined
  }
}

function decodeBase64(value: string): string | undefined {
  // 校验标准 base64：含填充时总长度须为 4 的倍数；去掉填充后长度 mod 4 不能为 1
  const unpadded = value.replace(/=+$/, "")
  if (unpadded.length < 8) return undefined
  if (unpadded.length % 4 === 1) return undefined
  if (!/^[A-Za-z0-9+/]+$/.test(unpadded)) return undefined

  const binary = atob(value)
  if (!mostlyPrintable(binary)) return undefined
  return binary
}

function decodeHex(value: string): string | undefined {
  if (value.length % 2 !== 0) return undefined
  const binary = Array.from({ length: value.length / 2 }, (_, i) =>
    String.fromCharCode(parseInt(value.slice(i * 2, i * 2 + 2), 16)),
  ).join("")
  if (!mostlyPrintable(binary)) return undefined
  return binary
}

function safeDecodeURIComponent(value: string): string | undefined {
  const decoded = decodeURIComponent(value)
  if (!mostlyPrintable(decoded)) return undefined
  return decoded
}

// 可打印判定：≥80% 字符为可打印 ASCII 或常见空白
function mostlyPrintable(value: string): boolean {
  if (value.length === 0) return false
  let printable = 0
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) printable++
  }
  return printable / value.length >= 0.8
}
