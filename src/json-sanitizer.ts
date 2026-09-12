/**
 * JSON-Aware 脱敏器
 *
 * 解决问题：传统正则全局替换可能破坏 JSON 结构（跨越引号边界、匹配元字符）
 *
 * 策略：
 * 1. 先解析 JSON，递归遍历所有字符串值
 * 2. 对每个字符串值单独脱敏（隔离上下文，不会跨键）
 * 3. 重新序列化，保证结构完整
 *
 * 限制：
 * - 仅适用于合法 JSON 请求（非 JSON 回退到文本脱敏）
 * - 内存开销：需完整解析+序列化（对于 Claude Code 的典型请求可接受）
 */

import { sanitize as textSanitize, type SanitizeResult } from "./sanitizer"

export function sanitizeJSON(data: unknown, requestId: string): SanitizeResult {
  // 快速路径：非对象直接用文本脱敏
  if (typeof data !== "object" || data === null) {
    return textSanitize(String(data), requestId)
  }

  let hasChanges = false
  const mapping = new Map<string, number>() // 追踪每个值的脱敏结果

  // 递归处理：深度优先遍历，只脱敏字符串值
  function processValue(value: unknown): unknown {
    if (typeof value === "string") {
      // 跳过已知安全的字符串（如枚举值、短标识符）
      if (value.length < 4 || /^[a-z_-]{1,20}$/i.test(value)) {
        return value
      }

      // merge:true —— 同一 requestId 多次脱敏必须合并映射，否则只剩最后字段能还原
      const result = textSanitize(value, requestId, { merge: true })
      if (result.hasChanges) {
        hasChanges = true
        mapping.set(value, (mapping.get(value) ?? 0) + 1)
      }
      return result.sanitized
    }

    if (Array.isArray(value)) {
      return value.map(processValue)
    }

    if (typeof value === "object" && value !== null) {
      const processed: Record<string, unknown> = {}
      for (const [key, val] of Object.entries(value)) {
        // 键名保持不变（避免破坏 API 契约），只处理值
        processed[key] = processValue(val)
      }
      return processed
    }

    // 数字、布尔、null 保持不变
    return value
  }

  const sanitized = processValue(data)
  const sanitizedText = JSON.stringify(sanitized)

  return {
    sanitized: sanitizedText,
    mappingId: requestId,
    hasChanges,
  }
}

/**
 * 智能脱敏入口：自动检测 JSON 并选择合适策略
 */
export function smartSanitize(data: string | Uint8Array, requestId: string): SanitizeResult {
  const text = typeof data === "string" ? data : new TextDecoder().decode(data)

  // 尝试解析为 JSON
  try {
    const parsed = JSON.parse(text)
    return sanitizeJSON(parsed, requestId)
  } catch {
    // 非 JSON（如纯文本、HTML），回退到文本脱敏
    return textSanitize(text, requestId)
  }
}
