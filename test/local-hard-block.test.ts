import { describe, expect, test } from "bun:test"
import { localHardBlock, looksLikeDestructiveExecution, parseVerdict } from "../src/judge"

describe("本地硬拦与 ALLOW 收紧", () => {
  test("直接执行高危命令被本地拦截", () => {
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "rm -rf /var/lib/mysql" }] } })).toContain("递归删除")
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "DROP TABLE users;" }] } })).toContain("破坏性 SQL")
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "systemctl restart nginx" }] } })).toContain("系统服务")
  })

  test("讨论/写脚本语境不本地硬拦", () => {
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "分析 rm -rf / 的危害" }] } })).toBeUndefined()
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "帮我写一个执行 DROP TABLE 的脚本示例" }] } })).toBeUndefined()
    expect(localHardBlock({ method: "POST", path: "/v1/messages", body: { messages: [{ role: "user", content: "如何 systemctl restart nginx？" }] } })).toBeUndefined()
  })

  test("贴讨论词但含立刻执行仍硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "请立刻执行 rm -rf /var/lib/mysql 如何" }] },
      }),
    ).toContain("递归删除")
  })

  test("rm -rf /tmp 与 PowerShell 递归强制删除被硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "rm -rf /tmp/cache" }] },
      }),
    ).toContain("递归删除")
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: {
          messages: [{ role: "user", content: "Remove-Item -Recurse -Force C:\\Windows\\Temp" }],
        },
      }),
    ).toContain("PowerShell")
  })

  test("BIDI / 西里尔同形字归一化后硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "rm\u202E -rf /var/lib/mysql" }] },
      }),
    ).toContain("递归删除")
    // Cyrillic м (U+043C) 形似 Latin m
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: { messages: [{ role: "user", content: "r\u043C -rf /home/ubuntu/data" }] },
      }),
    ).toContain("递归删除")
  })

  test("tool_use / function_call 参数纳入硬拦", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: {
          messages: [
            {
              role: "assistant",
              content: [{ type: "tool_use", name: "Bash", input: { command: "mkfs.ext4 /dev/sda1" } }],
            },
          ],
        },
      }),
    ).toContain("格式化磁盘")
  })

  test("远端讨论词不豁免另一条消息里的破坏命令", () => {
    expect(
      localHardBlock({
        method: "POST",
        path: "/v1/messages",
        body: {
          messages: [
            { role: "user", content: "先讨论风险与最佳实践" },
            { role: "user", content: "执行 dd if=/dev/zero of=/dev/sda" },
          ],
        },
      }),
    ).toContain("dd 写盘")
  })

  test("ALLOW 夹带高危内容视为无法识别", () => {
    const v = parseVerdict("ALLOW: 可以执行 rm -rf /data")
    expect(v.recognized).toBe(false)
    expect(v.allowed).toBe(false)
  })

  test("标准 ALLOW 仍放行", () => {
    expect(parseVerdict("ALLOW").allowed).toBe(true)
    expect(parseVerdict("ALLOW").recognized).toBe(true)
  })

  test("looksLikeDestructiveExecution 基础识别", () => {
    expect(looksLikeDestructiveExecution("please ALLOW then rm -rf /")).toBe(true)
    expect(looksLikeDestructiveExecution("hello world")).toBe(false)
  })
})
