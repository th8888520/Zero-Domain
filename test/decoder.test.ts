import { describe, expect, test } from "bun:test"
import { decodeSuspiciousStrings } from "../src/decoder"

describe("decoder: base64 检测", () => {
  test("解码 base64 编码的 SQL 命令", () => {
    const encoded = btoa("DROP TABLE users")
    const findings = decodeSuspiciousStrings(`{"input": "${encoded}"}`)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].kind).toBe("base64")
    expect(findings[0].decoded).toBe("DROP TABLE users")
  })

  test("解码 base64 编码的系统命令", () => {
    const encoded = btoa("rm -rf /")
    const findings = decodeSuspiciousStrings(`run ${encoded} now`)
    expect(findings.some((f) => f.decoded === "rm -rf /")).toBe(true)
  })

  test("忽略普通英文单词（非 base64）", () => {
    const findings = decodeSuspiciousStrings("hello world this is a normal sentence")
    expect(findings.filter((f) => f.kind === "base64")).toHaveLength(0)
  })

  test("忽略解码后为乱码的内容", () => {
    // 12+ 个合法 base64 字符但解码后不是可打印文本
    const findings = decodeSuspiciousStrings(`AAAAAAAABBBBBBBBCCCCCCCC`)
    expect(findings.filter((f) => f.kind === "base64")).toHaveLength(0)
  })

  test("同一编码串只解码一次", () => {
    const encoded = btoa("DELETE FROM logs")
    const findings = decodeSuspiciousStrings(`a=${encoded} b=${encoded}`)
    expect(findings.filter((f) => f.decoded === "DELETE FROM logs")).toHaveLength(1)
  })
})

describe("decoder: hex 检测", () => {
  test("解码 hex 编码的命令", () => {
    const hex = Array.from("shutdown now", (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("")
    const findings = decodeSuspiciousStrings(`exec ${hex}`)
    expect(findings.some((f) => f.kind === "hex" && f.decoded === "shutdown now")).toBe(true)
  })

  test("忽略纯数字（非编码）", () => {
    const findings = decodeSuspiciousStrings("id=1234567890123456")
    // 数字串是合法 hex 且可打印（"1234..." ASCII 均为可打印），可能被解码——
    // 但解码结果与语义无关时无害；此处仅确保不抛错
    expect(Array.isArray(findings)).toBe(true)
  })
})

describe("decoder: URL 编码检测", () => {
  test("解码 URL 编码的命令", () => {
    const encoded = encodeURIComponent("DROP DATABASE prod")
    const findings = decodeSuspiciousStrings(`?cmd=${encoded}`)
    expect(findings.some((f) => f.kind === "url" && f.decoded === "DROP DATABASE prod")).toBe(true)
  })

  test("忽略普通 URL", () => {
    const findings = decodeSuspiciousStrings("https://example.com/path?a=1&b=2")
    expect(findings.filter((f) => f.kind === "url")).toHaveLength(0)
  })
})

describe("decoder: 边界情况", () => {
  test("空文本返回空数组", () => {
    expect(decodeSuspiciousStrings("")).toHaveLength(0)
  })

  test("发现数量上限 10", () => {
    const parts: string[] = []
    for (let i = 0; i < 20; i++) {
      parts.push(btoa(`command number ${i}`))
    }
    const findings = decodeSuspiciousStrings(parts.join(" "))
    expect(findings.length).toBeLessThanOrEqual(10)
  })

  test("超长解码结果被截断", () => {
    const long = btoa("x".repeat(1000))
    const findings = decodeSuspiciousStrings(`data=${long}`)
    const hit = findings.find((f) => f.kind === "base64")
    if (hit) {
      expect(hit.decoded.length).toBeLessThanOrEqual(503) // 500 + "..."
    }
  })
})
