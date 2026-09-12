import { describe, expect, test } from "bun:test"
import { sanitizeJSON, smartSanitize } from "../src/json-sanitizer"

describe("JSON-Aware 脱敏器", () => {
  test("保证输出永远是合法 JSON", () => {
    const dangerous = {
      token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      email: "user@example.com",
      ip: "192.168.1.1",
      nested: {
        connStr: "mongodb://user:pass@host:27017/db",
        array: ["another@email.com", "10.0.0.1"],
      },
    }

    const result = sanitizeJSON(dangerous, "test-req-1")
    expect(result.hasChanges).toBe(true)

    // 关键：输出必须可解析
    const parsed = JSON.parse(result.sanitized)
    expect(parsed).toBeDefined()
    expect(typeof parsed.token).toBe("string")
    expect(parsed.token).toContain("{{") // 已脱敏

    // 嵌套结构完整
    expect(parsed.nested.connStr).toContain("{{")
    expect(Array.isArray(parsed.nested.array)).toBe(true)
  })

  test("跨多个键的敏感信息不会导致跨界匹配", () => {
    // 场景：模拟 830KB 请求，多处相同 token
    const large = {
      messages: Array.from({ length: 100 }, (_, i) => ({
        role: "user",
        content: `请求 ${i} 包含 token: eyJhbGci.payload.sign 和 IP 192.168.1.${i % 255}`,
      })),
    }

    const result = sanitizeJSON(large, "test-req-2")
    const parsed = JSON.parse(result.sanitized)

    // 结构完整：仍是 100 条消息
    expect(parsed.messages).toHaveLength(100)
    // 每条消息独立脱敏
    expect(parsed.messages[0].content).toContain("{{TOKEN")
    expect(parsed.messages[0].content).toContain("{{IP")
  })

  test("保持键名不变（避免破坏 API 契约）", () => {
    const data = { userEmail: "admin@company.com", "x-api-key": "secret123" }
    const result = sanitizeJSON(data, "test-req-3")
    const parsed = JSON.parse(result.sanitized)

    // 键名不脱敏
    expect(parsed.userEmail).toBeDefined()
    expect(parsed["x-api-key"]).toBeDefined()
    // 但值已脱敏
    expect(parsed.userEmail).not.toBe("admin@company.com")
  })

  test("smartSanitize 自动检测 JSON vs 文本", () => {
    // JSON 请求
    const json = JSON.stringify({ email: "test@x.com" })
    const r1 = smartSanitize(json, "req-1")
    expect(() => JSON.parse(r1.sanitized)).not.toThrow()

    // 纯文本
    const text = "Email me at contact@site.com"
    const r2 = smartSanitize(text, "req-2")
    expect(r2.sanitized).toContain("{{EMAIL")
    // 文本脱敏不保证 JSON（但原文也不是）
  })

  test("跳过短标识符和枚举值（性能优化）", () => {
    const data = {
      role: "user", // 4 字符，不脱敏
      model: "gpt-4", // 短枚举
      longText: "This contains email@example.com in text", // 长文本才脱敏
    }

    const result = sanitizeJSON(data, "test-req-4")
    const parsed = JSON.parse(result.sanitized)

    expect(parsed.role).toBe("user") // 未变
    expect(parsed.model).toBe("gpt-4") // 未变
    expect(parsed.longText).toContain("{{EMAIL") // 已脱敏
  })

  test("处理边界情况：空对象、null、数字", () => {
    const edge = {
      empty: {},
      nil: null,
      num: 12345,
      bool: true,
      nested: { array: [null, 0, false] },
    }

    const result = sanitizeJSON(edge, "test-req-5")
    const parsed = JSON.parse(result.sanitized)

    expect(parsed.empty).toEqual({})
    expect(parsed.nil).toBe(null)
    expect(parsed.num).toBe(12345)
    expect(parsed.bool).toBe(true)
  })
})
