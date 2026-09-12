/**
 * 敏感信息脱敏与还原模块
 *
 * 上行：请求体中的敏感信息 → 语义化占位符
 * 下行：占位符 → 原文还原（支持 SSE 流式）
 */

export interface SanitizeResult {
  sanitized: string
  mappingId: string
  hasChanges: boolean
}

export interface RestoreContext {
  mappingId: string
  data: string | Uint8Array
}

// 敏感信息匹配规则（按优先级排序：先匹配更具体的模式）
const PATTERNS = {
  // Token（JWT 或类似格式，最高优先级）
  // 支持标准 JWT 和测试用短 token（每部分 >= 3 字符）
  TOKEN: /\beyJ[a-zA-Z0-9_-]{3,}\.[a-zA-Z0-9_-]{3,}\.[a-zA-Z0-9_-]{3,}\b/g,

  // URL 中的敏感参数（必须在 TOKEN 之后，CONN_STR 之前）
  // 匹配参数值直到遇到 &、空格、引号或字符串结束，但排除 JWT token
  // 最小长度 6 以捕获更多短密钥
  URL_SENSITIVE_PARAM: /([?&](?:api_key|apikey|token|access_token|secret|key|auth)=)(?!eyJ)([^\s&"'<>]{6,})/gi,

  // 数据库连接串（避免 @ 被邮箱规则误捕获，但在 URL_SENSITIVE_PARAM 之后）
  CONN_STR: /(?:mongodb|mysql|postgresql|redis|mssql|oracle):\/\/[^\s"'<>]+/gi,

  // API Key 模式（OpenAI/Anthropic/Azure/通用密钥）
  // 放宽长度要求以支持测试密钥（最少 6 字符）
  API_KEY: /\b(?:sk-(?:ant-)?[a-zA-Z0-9]{6,}|(?:pk|xai)-[a-zA-Z0-9]{6,}|[a-f0-9]{32,64})\b/g,

  // AWS Access Key
  AWS_KEY: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,

  // 私钥整块（BEGIN 到 END，含中间材料；覆盖 RSA/EC/DSA/OPENSSH/ENCRYPTED/PKCS#8 等）
  PRIVATE_KEY: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----/gi,

  // 身份证号（18位）
  ID_CARD: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,

  // IP 地址（公网+内网）- 严格排除版本号格式
  // 后行断言 (?<!\d\.) 排除前面是数字+点的情况（如 "3.10.1.1" 中的 "10.1.1"）
  // 前瞻断言 (?!\.\d) 排除后面紧跟点和数字的情况（避免 "1.1.1.1.2"）
  IP_PUBLIC: /(?<!\d\.)(?<![\w@])(?:(?:[1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5]))(?!\.\d)(?![\w])/g,
  IP_PRIVATE: /(?<!\d\.)(?<![\w@])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\.\d)(?![\w])/g,

  // 电话号码（中国大陆）
  PHONE_CN: /\b1[3-9]\d{9}\b/g,

  // 邮箱（放在后面，避免误匹配 URI 和版本号）
  // 排除 npm 包格式（package@version）和版本号（x.y.z.w）
  EMAIL: /\b(?<![a-zA-Z0-9.-])[a-zA-Z0-9._%+-]+@(?![0-9]+\.)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b/g,

  // 敏感路径（包含用户名或家目录）
  PATH_USER: /(?:[C-Z]:\\Users\\[^\\]+|\/home\/[^\/]+|\/Users\/[^\/]+)/gi,

  // 密码字段值（必须用引号包裹；分组保留 key/语法，只替换值，避免破坏 JSON）
  PASSWORD_VALUE: /((?:password|passwd|pwd|secret)["']?\s*[:=]\s*["'])([^"']{4,})(["'])/gi,
} as const

type PatternKey = keyof typeof PATTERNS

// 映射表：requestId -> { 原文 -> 占位符 }
const mappingStore = new Map<string, Map<string, string>>()
// 反向映射：requestId -> { 占位符 -> 原文 }
const reverseMappingStore = new Map<string, Map<string, string>>()

// 映射表过期时间（5分钟）
const MAPPING_TTL_MS = 5 * 60 * 1000
/** 单请求最多保留多少个占位符，防止单包海量伪敏感串撑爆内存 */
const MAX_PLACEHOLDERS_PER_REQUEST = 500
/** 同时存活的请求映射上限；超出时淘汰最旧条目 */
const MAX_ACTIVE_REQUEST_MAPPINGS = 2_000
const expiryTimers = new Map<string, NodeJS.Timeout>()

export type SanitizeOptions = {
  /** 同一 requestId 多次调用时合并映射（JSON 多字段脱敏必须开启） */
  merge?: boolean
}

/**
 * 上行脱敏：将敏感信息替换为占位符
 */
export function sanitize(data: string | unknown, requestId: string, options?: SanitizeOptions): SanitizeResult {
  const text = typeof data === "string" ? data : JSON.stringify(data)
  const merge = options?.merge === true
  const mapping = merge && mappingStore.has(requestId)
    ? new Map(mappingStore.get(requestId)!)
    : new Map<string, string>()
  const reverseMapping = merge && reverseMappingStore.has(requestId)
    ? new Map(reverseMappingStore.get(requestId)!)
    : new Map<string, string>()
  const initialSize = mapping.size

  let sanitized = text
  let hasChanges = false

  const remember = (original: string, placeholder: string) => {
    if (mapping.has(original)) return mapping.get(original)!
    if (mapping.size >= MAX_PLACEHOLDERS_PER_REQUEST) return original
    mapping.set(original, placeholder)
    reverseMapping.set(placeholder, original)
    hasChanges = true
    return placeholder
  }

  // 应用所有匹配规则
  for (const [key, pattern] of Object.entries(PATTERNS)) {
    const regex = new RegExp(pattern.source, pattern.flags)

    // URL_SENSITIVE_PARAM / PASSWORD_VALUE：保留语法前缀，只替换值，避免把 JSON 结构替换坏
    if (key === "URL_SENSITIVE_PARAM") {
      sanitized = sanitized.replace(regex, (match, prefix, value) => {
        if (/^\{\{[A-Z_]+_[a-f0-9]{8}\}\}$/.test(value)) {
          return match
        }

        if (mapping.has(value)) {
          return `${prefix}${mapping.get(value)!}`
        }

        const placeholder = generatePlaceholder("API_KEY", value)
        const kept = remember(value, placeholder)
        return kept === value ? match : `${prefix}${kept}`
      })
    } else if (key === "PASSWORD_VALUE") {
      sanitized = sanitized.replace(regex, (match, prefix, value, suffix) => {
        if (/^\{\{[A-Z_]+_[a-f0-9]{8}\}\}$/.test(value)) {
          return match
        }

        if (mapping.has(value)) {
          return `${prefix}${mapping.get(value)!}${suffix}`
        }

        const placeholder = generatePlaceholder("PASSWORD_VALUE", value)
        const kept = remember(value, placeholder)
        return kept === value ? match : `${prefix}${kept}${suffix}`
      })
    } else {
      // 对于 IP 地址，需要额外检查上下文避免误捕获版本号
      if (key === "IP_PUBLIC" || key === "IP_PRIVATE") {
        const matches: Array<{ match: string; index: number }> = []
        let m
        while ((m = regex.exec(sanitized)) !== null) {
          matches.push({ match: m[0], index: m.index })
        }

        // 反向处理避免索引偏移问题
        for (let i = matches.length - 1; i >= 0; i--) {
          const { match, index } = matches[i]!

          // 检查是否已经是占位符
          if (/^\{\{[A-Z_]+_[a-f0-9]{8}\}\}$/.test(match)) {
            continue
          }

          // 检查前面的上下文，排除版本号场景
          // 版本号特征：前面有版本相关关键字、@ 符号、或已经是数字点序列
          const beforeContext = sanitized.substring(Math.max(0, index - 25), index)
          const isVersionNumber = /(?:Python|Version|v\d+|installed|release|update|package|axios|npm|@|version\s*:)\s*\d*\.?\d*\.?$/i.test(beforeContext)

          if (isVersionNumber) {
            continue // 跳过版本号
          }

          // 检查是否已有映射
          if (mapping.has(match)) {
            const placeholder = mapping.get(match)!
            sanitized = sanitized.substring(0, index) + placeholder + sanitized.substring(index + match.length)
            continue
          }

          // 生成新占位符
          const placeholder = generatePlaceholder(key as PatternKey, match)
          const kept = remember(match, placeholder)
          if (kept === match) continue
          sanitized = sanitized.substring(0, index) + kept + sanitized.substring(index + match.length)
        }
      } else {
        // 其他规则正常处理
        sanitized = sanitized.replace(regex, (match) => {
          // 检查是否已经是占位符
          if (/^\{\{[A-Z_]+_[a-f0-9]{8}\}\}$/.test(match)) {
            return match
          }

          // 检查是否已有映射
          if (mapping.has(match)) {
            return mapping.get(match)!
          }

          // 生成新占位符
          const placeholder = generatePlaceholder(key as PatternKey, match)
          return remember(match, placeholder)
        })
      }
    }
  }

  // 存储映射关系（merge 模式下保留同 requestId 的既有占位符）
  if (hasChanges || (merge && mapping.size > initialSize)) {
    ensureMappingCapacity(requestId)
    mappingStore.set(requestId, mapping)
    reverseMappingStore.set(requestId, reverseMapping)
    scheduleCleanup(requestId)
  }

  return {
    sanitized,
    mappingId: requestId,
    hasChanges: hasChanges || (merge && mapping.size > initialSize),
  }
}

/**
 * 下行还原：将占位符替换回原文
 */
export function restore(data: string | Uint8Array, mappingId: string): string | Uint8Array {
  const reverseMapping = reverseMappingStore.get(mappingId)
  if (!reverseMapping || reverseMapping.size === 0) {
    return data
  }

  const isBuffer = data instanceof Uint8Array
  let text = isBuffer ? new TextDecoder().decode(data) : data

  // 替换所有占位符
  for (const [placeholder, original] of reverseMapping.entries()) {
    // 转义正则特殊字符
    const escapedPlaceholder = placeholder.replace(/[{}]/g, '\\$&')
    const regex = new RegExp(escapedPlaceholder, 'g')
    text = text.replace(regex, original)
  }

  return isBuffer ? new TextEncoder().encode(text) : text
}

/**
 * SSE 流式还原：逐块还原
 * 支持占位符跨块的情况
 */
export class StreamRestorer {
  private buffer = ""
  private readonly reverseMapping: Map<string, string>

  constructor(mappingId: string) {
    this.reverseMapping = reverseMappingStore.get(mappingId) ?? new Map()
  }

  /**
   * 处理一个数据块
   */
  process(chunk: string): string {
    this.buffer += chunk

    // 查找完整的占位符并替换
    let restored = ""
    let lastIndex = 0
    const placeholderRegex = /\{\{[A-Z_]+_[a-f0-9]{8}\}\}/g

    let match: RegExpExecArray | null
    while ((match = placeholderRegex.exec(this.buffer)) !== null) {
      const placeholder = match[0]
      const original = this.reverseMapping.get(placeholder)

      // 添加占位符之前的内容
      restored += this.buffer.slice(lastIndex, match.index)
      // 添加还原后的原文（如果找到映射）或保持占位符
      restored += original !== undefined ? original : placeholder
      lastIndex = match.index + placeholder.length
    }

    // 处理剩余内容
    const remaining = this.buffer.slice(lastIndex)

    // 检查 remaining 末尾是否可能是不完整的占位符开头
    // 从末尾开始找最长的可能不完整占位符前缀
    let keepLength = 0
    for (let len = Math.min(remaining.length, 25); len > 0; len--) {
      const suffix = remaining.slice(-len)
      // 检查是否可能是占位符的开头部分
      if (/^\{(\{([A-Z_]{0,12}(_([a-f0-9]{0,8}\}?)?)?)?)?$/.test(suffix)) {
        keepLength = len
        break
      }
    }

    if (keepLength > 0) {
      // 保留可能不完整的部分
      restored += remaining.slice(0, -keepLength)
      this.buffer = remaining.slice(-keepLength)
    } else {
      // 全部输出
      restored += remaining
      this.buffer = ""
    }

    return restored
  }

  /**
   * 完成流处理，输出剩余内容
   */
  finalize(): string {
    // 最后尝试还原缓冲区中的内容
    if (this.buffer) {
      const placeholderRegex = /\{\{[A-Z_]+_[a-f0-9]{8}\}\}/g
      let match: RegExpExecArray | null
      let restored = ""
      let lastIndex = 0

      placeholderRegex.lastIndex = 0
      while ((match = placeholderRegex.exec(this.buffer)) !== null) {
        const placeholder = match[0]
        const original = this.reverseMapping.get(placeholder)

        restored += this.buffer.slice(lastIndex, match.index)
        restored += original !== undefined ? original : placeholder
        lastIndex = match.index + placeholder.length
      }

      restored += this.buffer.slice(lastIndex)
      this.buffer = ""
      return restored
    }
    return ""
  }
}

/**
 * 生成占位符
 *
 * 使用加密随机数而非值的哈希：占位符不可预测，防止攻击者在 prompt 中
 * 注入已知的确定性占位符（如 {{IP_<hash>}}）诱导下行还原成目标敏感值。
 * 同一请求内相同值只生成一次占位符（由 mapping 去重保证）。
 */
function generatePlaceholder(type: PatternKey, _value: string): string {
  const bytes = new Uint8Array(4)
  crypto.getRandomValues(bytes)
  const random = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")

  // 映射到语义化前缀
  const prefix = (() => {
    if (type.startsWith('IP_')) return 'IP'
    if (type.startsWith('PHONE_')) return 'PHONE'
    if (type === 'EMAIL') return 'EMAIL'
    if (type === 'ID_CARD') return 'IDCARD'
    if (type === 'CONN_STR') return 'CONNSTR'
    if (type === 'API_KEY') return 'APIKEY'
    if (type === 'AWS_KEY') return 'AWSKEY'
    if (type === 'PRIVATE_KEY') return 'PRIVKEY'
    if (type === 'PATH_USER') return 'PATH'
    if (type === 'PASSWORD_VALUE') return 'PASSWORD'
    if (type === 'TOKEN') return 'TOKEN'
    if (type === 'URL_SENSITIVE_PARAM') return 'APIKEY'
    return 'SENSITIVE'
  })()

  return `{{${prefix}_${random}}}`
}

/**
 * 调度清理任务
 */
function scheduleCleanup(requestId: string) {
  // 清除旧的定时器
  const oldTimer = expiryTimers.get(requestId)
  if (oldTimer) {
    clearTimeout(oldTimer)
  }

  // 设置新的定时器
  const timer = setTimeout(() => {
    mappingStore.delete(requestId)
    reverseMappingStore.delete(requestId)
    expiryTimers.delete(requestId)
  }, MAPPING_TTL_MS)

  expiryTimers.set(requestId, timer)
}

/** 超出全局活跃映射上限时淘汰最旧条目（Map 插入序） */
function ensureMappingCapacity(requestId: string) {
  if (mappingStore.has(requestId)) return
  while (mappingStore.size >= MAX_ACTIVE_REQUEST_MAPPINGS) {
    const oldest = mappingStore.keys().next().value as string | undefined
    if (!oldest) break
    cleanupMapping(oldest)
  }
}

/**
 * 手动清理映射
 */
export function cleanupMapping(requestId: string) {
  mappingStore.delete(requestId)
  reverseMappingStore.delete(requestId)

  const timer = expiryTimers.get(requestId)
  if (timer) {
    clearTimeout(timer)
    expiryTimers.delete(requestId)
  }
}

/**
 * 获取映射统计信息（用于审计）
 */
export function getStats() {
  return {
    activeMappings: mappingStore.size,
    totalPlaceholders: Array.from(mappingStore.values()).reduce((sum, map) => sum + map.size, 0),
  }
}

/**
 * 获取指定请求的脱敏计数（用于审计日志）
 */
export function getMappingCount(requestId: string): number {
  const mapping = mappingStore.get(requestId)
  return mapping ? mapping.size : 0
}
