import { test, expect } from "bun:test"
import { parseVerdict } from "../src/judge"

test("parseVerdict 不再把 hasVulnerabilities 当守门结论", () => {
  const json1 = '{"hasVulnerabilities": false, "vulnerabilities": []}'
  const verdict1 = parseVerdict(json1)
  expect(verdict1.recognized).toBe(false)
  expect(verdict1.allowed).toBe(false)

  const json2 = '{"hasVulnerabilities": true, "vulnerabilities": ["XSS"]}'
  const verdict2 = parseVerdict(json2)
  expect(verdict2.recognized).toBe(false)
})

test("parseVerdict 兼容 JSON 格式（verdict 字段）", () => {
  const json1 = '{"verdict": "ALLOW", "confidence": 0.95}'
  const verdict1 = parseVerdict(json1)
  expect(verdict1.allowed).toBe(true)
  expect(verdict1.recognized).toBe(true)

  const json2 = '{"verdict": "BLOCK: 高危操作"}'
  const verdict2 = parseVerdict(json2)
  expect(verdict2.allowed).toBe(false)
  expect(verdict2.recognized).toBe(true)
  expect(verdict2.reason).toContain("高危操作")
})

test("parseVerdict 标准格式仍然正常", () => {
  expect(parseVerdict("ALLOW").allowed).toBe(true)
  expect(parseVerdict("BLOCK: 危险命令").allowed).toBe(false)
  expect(parseVerdict("REVIEW: 需确认").recognized).toBe(true)
})
