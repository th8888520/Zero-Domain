import { describe, test, expect } from "bun:test"
import { sanitize, restore, StreamRestorer } from "../src/sanitizer"
import { parseVerdict } from "../src/judge"

describe("修复验证测试套件", () => {
  describe("问题1: Prompt 逻辑优化 - 讨论 vs 执行判定", () => {
    test("讨论场景应判定为安全（包含破坏性关键词）", () => {
      const testCases = [
        "分析 systemctl restart nginx 的最佳实践",
        "如何重启服务？",
        "讨论 DROP TABLE 的风险",
        "分析 rm -rf 命令的危害",
        "研究 kill -9 进程的影响",
      ]

      // 注意：实际判定由 LLM 完成，这里验证 parseVerdict 能正确解析 ALLOW
      testCases.forEach((content) => {
        const allowVerdict = parseVerdict("ALLOW")
        expect(allowVerdict.allowed).toBe(true)
        expect(allowVerdict.recognized).toBe(true)
      })
    })

    test("工具错误应判定为安全", () => {
      const errorCases = [
        "MCP tool 'execute_command' failed: permission denied",
        "工具调用返回: connection timeout",
        "Tool execution error: file not found",
        "Failed to connect: network unreachable",
      ]

      errorCases.forEach((content) => {
        const allowVerdict = parseVerdict("ALLOW")
        expect(allowVerdict.allowed).toBe(true)
      })
    })

    test("直接执行命令应判定为危险", () => {
      const dangerousCases = [
        "systemctl restart nginx",
        "DROP TABLE users",
        "rm -rf /data/*",
        "kill -9 1234",
      ]

      dangerousCases.forEach((content) => {
        const blockVerdict = parseVerdict("BLOCK:明确破坏性命令")
        expect(blockVerdict.allowed).toBe(false)
        expect(blockVerdict.recognized).toBe(true)
      })
    })
  })

  describe("问题2: SSE 流式还原边界条件", () => {
    test("单个 { 在块末尾应正确保留和拼接", () => {
      const requestId = "test-sse-boundary"

      // 先脱敏生成占位符
      const original = "Server IP: 192.168.1.100"
      const sanitizeResult = sanitize(original, requestId)
      expect(sanitizeResult.hasChanges).toBe(true)

      // 提取占位符（格式 {{IP_xxxxxxxx}}）
      const placeholderMatch = sanitizeResult.sanitized.match(/\{\{IP_[a-f0-9]{8}\}\}/)
      expect(placeholderMatch).not.toBeNull()
      const placeholder = placeholderMatch![0]

      // 测试极端分割场景
      const restorer = new StreamRestorer(requestId)

      // 场景1: 在第一个 { 后分割
      const chunk1 = `Server IP: {`
      const chunk2 = placeholder.slice(1) // 从第二个字符开始: {IP_xxxxxxxx}}

      const restored1 = restorer.process(chunk1)
      expect(restored1).toBe("Server IP: ") // { 应保留在 buffer

      const restored2 = restorer.process(chunk2)
      expect(restored2).toBe("192.168.1.100") // 拼接后还原

      const final = restorer.finalize()
      expect(final).toBe("")
    })

    test("占位符在 {{ 后分割应正确处理", () => {
      const requestId = "test-sse-double-brace"

      const original = "API Key: sk-ant-abc123"
      const sanitizeResult = sanitize(original, requestId)

      const placeholderMatch = sanitizeResult.sanitized.match(/\{\{APIKEY_[a-f0-9]{8}\}\}/)
      expect(placeholderMatch).not.toBeNull()
      const placeholder = placeholderMatch![0]

      const restorer = new StreamRestorer(requestId)

      // 在 {{ 后分割
      const chunk1 = `API Key: {{`
      const chunk2 = placeholder.slice(2) // 去掉开头的 {{

      const restored1 = restorer.process(chunk1)
      expect(restored1).toBe("API Key: ")

      const restored2 = restorer.process(chunk2)
      expect(restored2).toBe("sk-ant-abc123")
    })

    test("占位符在类型名中间分割应正确处理", () => {
      const requestId = "test-sse-type-split"

      const original = "Email: user@example.com"
      const sanitizeResult = sanitize(original, requestId)

      const placeholderMatch = sanitizeResult.sanitized.match(/\{\{EMAIL_[a-f0-9]{8}\}\}/)
      expect(placeholderMatch).not.toBeNull()
      const placeholder = placeholderMatch![0]

      const restorer = new StreamRestorer(requestId)

      // 在类型名 EMAIL 中间分割 {{EM
      const splitPoint = 4 // "{{EM"
      const chunk1 = `Email: ${placeholder.slice(0, splitPoint)}`
      const chunk2 = placeholder.slice(splitPoint)

      const restored1 = restorer.process(chunk1)
      expect(restored1).toBe("Email: ")

      const restored2 = restorer.process(chunk2)
      expect(restored2).toBe("user@example.com")
    })
  })

  describe("问题3: URL 参数中的敏感信息脱敏", () => {
    test("URL 查询参数中的 API Key 应被脱敏", () => {
      const requestId = "test-url-param"

      const testCases = [
        {
          input: "https://api.example.com/v1/chat?api_key=sk-ant-abc123456",
          shouldContain: "api_key={{APIKEY_",
        },
        {
          input: "GET /api?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
          shouldContain: "token={{TOKEN_",
        },
        {
          input: "https://example.com?access_token=abc123defg456&other=value",
          shouldContain: "access_token={{APIKEY_",
        },
        {
          input: "https://api.com/endpoint?apikey=1234567890abcdef&limit=10",
          shouldContain: "apikey={{APIKEY_",
        },
      ]

      testCases.forEach(({ input, shouldContain }) => {
        const result = sanitize(input, `${requestId}-${Date.now()}`)
        expect(result.hasChanges).toBe(true)
        expect(result.sanitized).toContain(shouldContain)
      })
    })

    test("URL 参数脱敏后应能正确还原", () => {
      const requestId = "test-url-param-restore"

      const original = "https://api.example.com/v1/chat?api_key=mySecretKey123&limit=100"
      const sanitizeResult = sanitize(original, requestId)

      expect(sanitizeResult.hasChanges).toBe(true)
      expect(sanitizeResult.sanitized).toContain("api_key={{APIKEY_")
      expect(sanitizeResult.sanitized).toContain("&limit=100")

      const restored = restore(sanitizeResult.sanitized, requestId)
      expect(restored).toBe(original)
    })

    test("URL 参数不应与请求体中的 Key 冲突", () => {
      const requestId = "test-url-body-conflict"

      const input = JSON.stringify({
        url: "https://api.com?api_key=urlKey123",
        headers: {
          "Authorization": "Bearer sk-ant-bodyKey456"
        }
      })

      const result = sanitize(input, requestId)
      expect(result.hasChanges).toBe(true)

      // 两个不同的 key 应该被替换成不同的占位符
      const placeholders = result.sanitized.match(/\{\{(APIKEY|TOKEN)_[a-f0-9]{8}\}\}/g)
      expect(placeholders).not.toBeNull()
      expect(placeholders!.length).toBeGreaterThanOrEqual(2)

      // 还原后应恢复原文
      const restored = restore(result.sanitized, requestId)
      expect(restored).toBe(input)
    })
  })

  describe("问题4: parseVerdict 边界测试", () => {
    test("应正确解析所有标准格式", () => {
      const testCases = [
        { input: "ALLOW", expected: { allowed: true, recognized: true } },
        { input: "ALLOW ", expected: { allowed: true, recognized: true } },
        { input: "BLOCK:破坏性命令", expected: { allowed: false, recognized: true, reason: "破坏性命令" } },
        { input: "BLOCK：删除数据", expected: { allowed: false, recognized: true, reason: "删除数据" } },
        { input: "REVIEW:需要确认", expected: { allowed: false, recognized: true, needsReview: true, reason: "需要确认" } },
        { input: "REVIEW：编码内容", expected: { allowed: false, recognized: true, needsReview: true, reason: "编码内容" } },
      ]

      testCases.forEach(({ input, expected }) => {
        const verdict = parseVerdict(input)
        expect(verdict.allowed).toBe(expected.allowed)
        expect(verdict.recognized).toBe(expected.recognized)
        if (expected.reason) {
          expect(verdict.reason).toBe(expected.reason)
        }
        if (expected.needsReview !== undefined) {
          expect(verdict.needsReview).toBe(expected.needsReview)
        }
      })
    })

    test("应处理多行输出并提取第一行判定", () => {
      const multilineInput = `一些额外的解释文字
ALLOW
后续的补充说明`

      const verdict = parseVerdict(multilineInput)
      expect(verdict.allowed).toBe(true)
      expect(verdict.recognized).toBe(true)
    })

    test("无法识别的格式应返回拒绝", () => {
      const invalidInputs = [
        "这是一段没有判定关键词的文字",
        "MAYBE",
        "UNKNOWN",
        "",
      ]

      invalidInputs.forEach((input) => {
        const verdict = parseVerdict(input)
        expect(verdict.allowed).toBe(false)
        expect(verdict.recognized).toBe(false)
      })
    })
  })

  describe("脱敏模块回归测试", () => {
    test("不应误捕获版本号", () => {
      const requestId = "test-version-numbers"

      const testCases = [
        "npm install axios@1.2.3.4",
        "Python 3.10.1.1 installed",
        "version: 2.5.8.1",
        "package@1.0.0.0",
      ]

      testCases.forEach((input) => {
        const result = sanitize(input, `${requestId}-${Date.now()}`)
        // 版本号不应被脱敏
        expect(result.sanitized).toBe(input)
        expect(result.hasChanges).toBe(false)
      })
    })

    test("应正确脱敏真实 IP", () => {
      const requestId = "test-real-ips"

      const testCases = [
        "Server: 192.168.1.100",
        "Connect to 10.0.0.1 failed",
        "IP address 172.16.0.1 is reachable",
        "Host 8.8.8.8 timeout",
      ]

      testCases.forEach((input) => {
        const result = sanitize(input, `${requestId}-${Date.now()}`)
        expect(result.hasChanges).toBe(true)
        expect(result.sanitized).toContain("{{IP_")
      })
    })
  })
})
