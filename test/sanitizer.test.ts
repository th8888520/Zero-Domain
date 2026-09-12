import { describe, test, expect } from "bun:test"
import { sanitize, restore, StreamRestorer, cleanupMapping, getStats } from "../src/sanitizer"

describe("敏感信息脱敏", () => {
  test("IP 地址脱敏", () => {
    const data = "服务器地址是 192.168.1.100 和公网 8.8.8.8"
    const result = sanitize(data, "test-ip")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{IP_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("192.168.1.100")
    expect(result.sanitized).not.toContain("8.8.8.8")

    // 还原
    const restored = restore(result.sanitized, "test-ip")
    expect(restored).toBe(data)

    cleanupMapping("test-ip")
  })

  test("电话号码脱敏", () => {
    const data = "联系方式：13812345678"
    const result = sanitize(data, "test-phone")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{PHONE_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("13812345678")

    const restored = restore(result.sanitized, "test-phone")
    expect(restored).toBe(data)

    cleanupMapping("test-phone")
  })

  test("邮箱脱敏", () => {
    const data = "发送到 user@example.com"
    const result = sanitize(data, "test-email")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{EMAIL_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("user@example.com")

    const restored = restore(result.sanitized, "test-email")
    expect(restored).toBe(data)

    cleanupMapping("test-email")
  })

  test("数据库连接串脱敏", () => {
    const data = "连接: mongodb://user:pass@localhost:27017/db"
    const result = sanitize(data, "test-conn")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{CONNSTR_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("mongodb://")

    const restored = restore(result.sanitized, "test-conn")
    expect(restored).toBe(data)

    cleanupMapping("test-conn")
  })

  test("API Key 脱敏", () => {
    const data = "密钥: sk-1234567890abcdefghijklmnopqrstuvwxyz"
    const result = sanitize(data, "test-apikey")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{APIKEY_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("sk-1234567890")

    const restored = restore(result.sanitized, "test-apikey")
    expect(restored).toBe(data)

    cleanupMapping("test-apikey")
  })

  test("路径脱敏", () => {
    const data = "文件在 C:\\Users\\admin\\secret.txt"
    const result = sanitize(data, "test-path")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{PATH_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("C:\\Users\\admin")

    const restored = restore(result.sanitized, "test-path")
    expect(restored).toBe(data)

    cleanupMapping("test-path")
  })

  test("JWT Token 脱敏", () => {
    const data = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    const result = sanitize(data, "test-token")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toMatch(/\{\{TOKEN_[a-f0-9]{8}\}\}/)
    expect(result.sanitized).not.toContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

    const restored = restore(result.sanitized, "test-token")
    expect(restored).toBe(data)

    cleanupMapping("test-token")
  })

  test("混合敏感信息脱敏", () => {
    const data = `{
      "ip": "192.168.1.1",
      "phone": "13900139000",
      "email": "admin@example.com",
      "conn": "mysql://root:password@localhost:3306/db"
    }`
    const result = sanitize(data, "test-mixed")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).not.toContain("192.168.1.1")
    expect(result.sanitized).not.toContain("13900139000")
    expect(result.sanitized).not.toContain("admin@example.com")
    expect(result.sanitized).not.toContain("mysql://")

    const restored = restore(result.sanitized, "test-mixed")
    expect(restored).toBe(data)

    cleanupMapping("test-mixed")
  })

  test("无敏感信息时不修改", () => {
    const data = "这是普通文本，没有敏感信息"
    const result = sanitize(data, "test-clean")

    expect(result.hasChanges).toBe(false)
    expect(result.sanitized).toBe(data)

    cleanupMapping("test-clean")
  })

  test("已脱敏的占位符不重复处理", () => {
    const data = "IP: {{IP_12345678}} 和 192.168.1.1"
    const result = sanitize(data, "test-placeholder")

    expect(result.hasChanges).toBe(true)
    expect(result.sanitized).toContain("{{IP_12345678}}")
    expect(result.sanitized).not.toContain("192.168.1.1")

    cleanupMapping("test-placeholder")
  })

  test("JSON password/secret 字段只替换值且保持可解析", () => {
    const data = JSON.stringify({
      password: "mysecretpass",
      secret: "abcdefghi",
      model: "claude-sonnet",
    })
    const result = sanitize(data, "test-json-password")

    expect(result.hasChanges).toBe(true)
    expect(() => JSON.parse(result.sanitized)).not.toThrow()
    const parsed = JSON.parse(result.sanitized) as Record<string, string>
    expect(parsed.model).toBe("claude-sonnet")
    expect(parsed.password).toMatch(/^\{\{PASSWORD_[a-f0-9]{8}\}\}$/)
    expect(parsed.secret).toMatch(/^\{\{PASSWORD_[a-f0-9]{8}\}\}$/)
    expect(result.sanitized).not.toContain("mysecretpass")
    expect(result.sanitized).not.toContain("abcdefghi")

    const restored = restore(result.sanitized, "test-json-password")
    expect(restored).toBe(data)

    cleanupMapping("test-json-password")
  })
})

describe("SSE 流式还原", () => {
  test("单块完整占位符还原", () => {
    const original = "IP: 192.168.1.1"
    const sanitizeResult = sanitize(original, "stream-1")

    const restorer = new StreamRestorer("stream-1")
    const restored = restorer.process(sanitizeResult.sanitized)
    const final = restorer.finalize()

    expect(restored + final).toBe(original)
    cleanupMapping("stream-1")
  })

  test("占位符跨块处理", () => {
    const original = "服务器 192.168.1.1 在线"
    const sanitizeResult = sanitize(original, "stream-2")
    const placeholder = sanitizeResult.sanitized.match(/\{\{IP_[a-f0-9]{8}\}\}/)?.[0]

    expect(placeholder).toBeDefined()

    // 模拟占位符被分割到两个块
    const mid = Math.floor(placeholder!.length / 2)
    const chunk1 = sanitizeResult.sanitized.slice(0, sanitizeResult.sanitized.indexOf(placeholder!) + mid)
    const chunk2 = sanitizeResult.sanitized.slice(sanitizeResult.sanitized.indexOf(placeholder!) + mid)

    const restorer = new StreamRestorer("stream-2")
    const part1 = restorer.process(chunk1)
    const part2 = restorer.process(chunk2)
    const final = restorer.finalize()

    const restored = part1 + part2 + final
    expect(restored).toBe(original)

    cleanupMapping("stream-2")
  })

  test("多块流式还原", () => {
    const original = "IP1: 192.168.1.1, IP2: 10.0.0.1, IP3: 172.16.0.1"
    const sanitizeResult = sanitize(original, "stream-3")

    // 模拟分块传输
    const chunks = []
    const chunkSize = 20
    for (let i = 0; i < sanitizeResult.sanitized.length; i += chunkSize) {
      chunks.push(sanitizeResult.sanitized.slice(i, i + chunkSize))
    }

    const restorer = new StreamRestorer("stream-3")
    let restored = ""
    for (const chunk of chunks) {
      restored += restorer.process(chunk)
    }
    restored += restorer.finalize()

    expect(restored).toBe(original)
    cleanupMapping("stream-3")
  })
})

describe("统计与清理", () => {
  test("统计信息正确", () => {
    sanitize("IP: 192.168.1.1", "stats-1")
    sanitize("Phone: 13812345678", "stats-2")

    const stats = getStats()
    expect(stats.activeMappings).toBeGreaterThanOrEqual(2)
    expect(stats.totalPlaceholders).toBeGreaterThanOrEqual(2)

    cleanupMapping("stats-1")
    cleanupMapping("stats-2")
  })

  test("手动清理映射", () => {
    const data = "IP: 192.168.1.1"
    sanitize(data, "cleanup-test")

    const before = getStats()
    cleanupMapping("cleanup-test")
    const after = getStats()

    expect(after.activeMappings).toBeLessThan(before.activeMappings)
  })
})
