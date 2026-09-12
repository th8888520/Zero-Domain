# 零域（Zero Domain）

**本机 AI 安全网关** — 夹在 Claude Code / Codex CLI 与上游 API 之间，做脱敏、审查与审计。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 171](https://img.shields.io/badge/Tests-171%20passing-brightgreen)](https://github.com)

包名：`zero-domain`　运行时：Bun ≥ 1.0　语言：TypeScript

## 设计初衷

最近模型侧的**信息泄露**屡见报端（含多家大厂）；也确实遇到过模型**不守约束、自行执行高危命令**的时刻——删库类事故并非都市传说。与此同时，营销号热衷鼓吹「AI 全自动挖洞、月入多少万」：不少人拿着模型和 skill，便以为已是高手，不问后果先猛干一气，却看不见风险正在逼近。

**零域（Zero Domain）因此而生**——不是又一个模型中转站，而是夹在客户端与上游之间的本机安全闸：

| 能力 | 做什么 |
|------|--------|
| **流式 / 请求前脱敏** | 在请求发出前替换敏感数据，降低 AI 自动上传密钥、内网信息、连接串等造成的泄露 |
| **LLM 双重审查** | 请求发出前审查即将执行的操作，拦截破坏性命令；在事故发生前阻断，而不是事后补救 |
| **请求溯源** | 记录每一条 AI 请求的放行与拦截，一查便知 |

用 AI 编程客户端时，对话和工具调用本会直达上游。零域在本机拦一道：业务模型仍走你配置的上游，审查模型单独配置，只负责放行或拦截。

```
AI 客户端  ──▶  零域 (127.0.0.1:8787)  ──▶  上游 API
                  脱敏 → 审查 → 转发 → 还原
                       + 审计
```

更完整的用途与特点说明见 **[项目介绍.md](项目介绍.md)**。

---

## 功能与特点

- **JSON-Aware 脱敏** — 结构化脱敏保证输出永远是合法 JSON；连接串 / JWT / API Key / AWS / 整块 PEM（含 ENCRYPTED、DSA）/ 身份证 / IP / 手机 / 邮箱 / 路径 / password 等自动替换；SSE 边收边还原
- **编码绕过防护** — 送审前解码 base64/hex/URL；硬拦路径「解码即检」、尾部优先，抗 decoy / 前缀填充
- **LLM 一审 / 二审 + 本地硬拦** — 明显破坏命令可本地直接拦（含 `/tmp`、PowerShell、同形字/BIDI）；LLM 放行后再复核；默认 `REVIEW_MODE=llm` + `REVIEW_FAIL_OPEN=false`
- **完整审计** — JSONL 落盘、约 100MB rename 轮转；读写经同一写队列；终端可只打拦截摘要
- **透传认证** — `PROXY_AUTH_PASSTHROUGH=true` 时客户端只改 Base URL，原 Key 原样上行（仍脱敏/审查/审计；不注入配置里的上游 Key）
- **客户端托管（可选）** — 自动改写 Claude `settings.json` / Codex `config.toml`，退出按字节还原（备份后缀 `.zero-domain.backup`）
- **CCSwitch 上游** — `UPSTREAM_SOURCE=ccswitch` 跟随当前 provider；无文件内凭证时整包回退，禁止「外部 URL + 本地 Key」混绑
- **管理后台** — 仪表板 / 审计分页 / 拦截详情 / 配置页（审查开关文案、密钥轮换提醒）/ `.env` 在线编辑（密钥脱敏、禁写回 `***`）
- **配置白名单** — 严格校验；`LISTEN_HOST` / 路径类键不可经管理面改写
- **依赖面小** — 运行时第三方仅 `smol-toml`（Codex TOML）

---

## 快速开始

```bash
bun install
cp .env.example .env
# 编辑 .env：UPSTREAM_*、PROXY_API_KEY、PROXY_ADMIN_TOKEN、REVIEW_*（审查开启时）
bun run start
```

**Claude Code**（透传示例）：把 `~/.claude/settings.json` 里的 Base URL 指到代理即可：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  }
}
```

并在 `.env` 中设置：

```env
PROXY_AUTH_PASSTHROUGH=true
CLAUDE_SETTINGS_AUTO=false
CODEX_SETTINGS_AUTO=false
```

**Windows 一键**：`start.bat` / `stop.bat` / `restart.bat`（会备份并改写 Claude Base URL，启动后打开管理页）。

---

## 核心配置（摘要）

```env
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8787

UPSTREAM_URL=https://api.anthropic.com
UPSTREAM_API_KEY=your-api-key
# 或 UPSTREAM_SOURCE=ccswitch 跟随 ~/.claude/settings.json

PROXY_API_KEY=proxy-local-token
PROXY_ADMIN_TOKEN=change-me
PROXY_AUTH_PASSTHROUGH=true

# 审查总开关：llm=本地硬拦+LLM（默认）；off=整段审查关闭（仍脱敏/审计/转发）
REVIEW_MODE=llm
REVIEW_PROVIDER=openai-chat   # anthropic | openai-chat | openai-responses | codex
REVIEW_BASE_URL=https://api.openai.com
REVIEW_API_KEY=your-review-key
REVIEW_MODEL=gpt-4o-mini
# 审查故障策略：false=故障拦截（默认）；true=故障放行（仅临时排障）
REVIEW_FAIL_OPEN=false
```

| 配置 | 作用 | 推荐 |
|------|------|------|
| `REVIEW_MODE=llm` | 开审查：本地硬拦 + LLM | **默认，生产保持** |
| `REVIEW_MODE=off` | 关审查闸（硬拦和 LLM 都不跑） | 仅临时排障 |
| `REVIEW_FAIL_OPEN=false` | 审查模型挂了就拦截 | **默认，生产保持** |
| `REVIEW_FAIL_OPEN=true` | 审查模型挂了仍放行 | 不推荐 |

完整变量列表见 [.env.example](.env.example)。  
注意：`data/zero-domain.config.json` 里的持久化项**优先于** `.env`。

---

## 管理后台

打开 [http://127.0.0.1:8787/admin](http://127.0.0.1:8787/admin)，在页面输入 `PROXY_ADMIN_TOKEN` 后点「连接」：

- 统计仪表板、审计日志、运行配置查看、.env 在线编辑
- **审计日志**：服务端分页；点「加载更多」或翻到末页继续拉取历史
- **拦截详情**：原因、审查判定行、被拦截原文（红色 `BLOCKED`；需 `AUDIT_INCLUDE_BODY=blocked|all`）
- **配置页**：CCS 实时上游 + 回退上游；审查模式显示「开启（硬拦+LLM）」；**密钥轮换提醒**（持久化字段 / ≥30 天建议更换；只显示末四位）
- **.env 编辑**：GET 对 KEY/TOKEN 脱敏为 `***`；禁止把 `***` 原样写回
- 静态资源：`src/admin/static/`；健康检查：`GET /healthz`（免认证）

`data/zero-domain.config.json` 与 `*.secrets-meta.json` 已在 `.gitignore` 的 `data/` 下，**勿提交仓库**。

常用审计 API：

```http
GET /admin/api/audit/stats
GET /admin/api/audit?limit=50&offset=0
GET /admin/api/audit?verdict=block&limit=100
GET /admin/api/audit?id=<record-id>          # 详情（含截断后的 requestBody）
GET /admin/api/audit?includeBody=1&limit=20  # 列表也带 body（慎用）
```

要看到拦截原文，请确保：

```env
AUDIT_INCLUDE_BODY=blocked   # 或 all
PROXY_ADMIN_TOKEN=你的令牌
```

旧记录若产生时未开启正文落盘，详情会提示「审计未保存请求体」。概括性拦截原因若未逐字出现在请求体中，会整段标记原文并说明未能精确定位命中片段。

页面「清空显示」只清前端表格；服务端审计删除走管理 API，删除动作本身会追加审计记录。

---

## 文档

| 文档 | 内容 |
|------|------|
| [项目介绍.md](项目介绍.md) | **用途、功能与特点**（推荐先读） |
| [.env.example](.env.example) | 全量环境变量说明 |

---

## 常用命令

```bash
bun run start       # 启动
bun run dev         # watch 模式
bun test            # 测试
bun run typecheck   # tsc --noEmit
```

---

## 许可

MIT License
