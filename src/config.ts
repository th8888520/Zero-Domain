import { DEFAULT_ADMIN_CONFIG_PATH } from "./config-store"

export type JudgeProvider = "anthropic" | "openai-responses" | "openai-chat" | "codex"
export type UpstreamAuthMode = "preserve" | "anthropic" | "bearer"
export type UpstreamSource = "static" | "ccswitch"
export type ReviewMode = "off" | "llm"
export type ReviewScope = "all" | "api"
export type AuditStdoutMode = "off" | "blocked" | "all"
export type AuditIncludeBodyMode = "off" | "blocked" | "all"

export interface ProxyConfig {
  listenHost: string
  listenPort: number
  upstreamURL: string
  upstreamAPIKey?: string
  upstreamAuthMode: UpstreamAuthMode
  upstreamSource: UpstreamSource
  ccswitchSettingsPath: string
  claudeSettingsAuto: boolean
  claudeSettingsPath: string
  claudeProxyURL?: string
  claudeProxyAPIKey: string
  codexSettingsAuto: boolean
  codexConfigPath: string
  codexProxyURL?: string
  codexProxyAPIKey: string
  codexUpstreamURL?: string
  codexUpstreamExplicit: boolean
  proxyAPIKey: string
  proxyAuthPassthrough: boolean
  adminToken: string
  maxRequestBytes: number
  upstreamTimeoutMs: number
  reviewMode: ReviewMode
  reviewScope: ReviewScope
  judgeEnabled: boolean
  judgeProvider: JudgeProvider
  judgeBaseURL: string
  judgeAPIKey?: string
  judgeModel: string
  judgeTimeoutMs: number
  judgeMaxOutputTokens: number
  judgeMaxInputChars: number
  judgeMaxMessages: number
  judgeMaxConcurrent: number
  judgeMinIntervalMs: number
  judgeQueueSize: number
  judgeQueueBytes: number
  judgeMaxRetries: number
  judgeRetryBaseMs: number
  judgeFailOpen: boolean
  disconnectOnBlock: boolean
  judgePrompt?: string
  judgeAccountID?: string
  auditPath: string
  auditIncludeBody: AuditIncludeBodyMode
  auditStdout: AuditStdoutMode
  adminConfigPath?: string
}

const DEFAULT_LISTEN_HOST = "127.0.0.1"
const DEFAULT_LISTEN_PORT = 8787
const DEFAULT_MAX_REQUEST_BYTES = 10 * 1024 * 1024
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120_000
const DEFAULT_JUDGE_TIMEOUT_MS = 8_000
const DEFAULT_JUDGE_MAX_OUTPUT_TOKENS = 512
const DEFAULT_JUDGE_MAX_INPUT_CHARS = 24_000
const DEFAULT_JUDGE_MAX_MESSAGES = 12
const DEFAULT_REVIEW_SCOPE: ReviewScope = "all"
const DEFAULT_JUDGE_MAX_CONCURRENT = 2
const DEFAULT_JUDGE_MIN_INTERVAL_MS = 100
const DEFAULT_JUDGE_QUEUE_SIZE = 32
const DEFAULT_JUDGE_QUEUE_BYTES = 64 * 1024 * 1024
const DEFAULT_JUDGE_MAX_RETRIES = 2
const DEFAULT_JUDGE_RETRY_BASE_MS = 250
const DEFAULT_AUDIT_PATH = "./data/zero-domain.audit.jsonl"

export function loadConfig(env: Record<string, string | undefined> = Bun.env): ProxyConfig {
  const defaultSettingsPath = defaultCCSwitchSettingsPath(env)
  const clientPaths = clientSettingsPaths(env)
  const listenHost = env.LISTEN_HOST ?? DEFAULT_LISTEN_HOST
  const listenPort = parseInteger(env.LISTEN_PORT, DEFAULT_LISTEN_PORT, "LISTEN_PORT")
  const upstreamURL = normalizeURL(required(env.UPSTREAM_URL, "UPSTREAM_URL"), "UPSTREAM_URL")
  const codexUpstreamURL = env.CODEX_UPSTREAM_URL
    ? normalizeURL(env.CODEX_UPSTREAM_URL, "CODEX_UPSTREAM_URL")
    : undefined
  if (codexUpstreamURL && isProxyEndpoint(codexUpstreamURL, { listenHost, listenPort })) {
    throw new Error("CODEX_UPSTREAM_URL must not point to this proxy")
  }
  const reviewMode = parseReviewMode(prefer(env.REVIEW_MODE, legacyReviewMode(env.JUDGE_ENABLED)))
  const judgeProvider = parseJudgeProvider(prefer(env.REVIEW_PROVIDER, env.JUDGE_PROVIDER))
  const judgeEnabled = reviewMode === "llm"
  const judgeBaseURL = normalizeURL(
    prefer(env.REVIEW_BASE_URL, env.JUDGE_BASE_URL) ?? defaultJudgeBaseURL(judgeProvider),
    preferName(env.REVIEW_BASE_URL, env.JUDGE_BASE_URL, "REVIEW_BASE_URL", "JUDGE_BASE_URL"),
  )

  return {
    listenHost,
    listenPort,
    upstreamURL,
    upstreamAPIKey: env.UPSTREAM_API_KEY,
    upstreamAuthMode: parseUpstreamAuthMode(env.UPSTREAM_AUTH_MODE),
    upstreamSource: parseUpstreamSource(env.UPSTREAM_SOURCE),
    ccswitchSettingsPath: expandHomePath(env.CCSWITCH_SETTINGS_PATH ?? defaultSettingsPath, env),
    claudeSettingsAuto: parseBoolean(env.CLAUDE_SETTINGS_AUTO, false),
    claudeSettingsPath: clientPaths.claudeSettingsPath,
    claudeProxyURL: env.CLAUDE_PROXY_URL
      ? normalizeURL(env.CLAUDE_PROXY_URL, "CLAUDE_PROXY_URL")
      : undefined,
    claudeProxyAPIKey: env.CLAUDE_PROXY_API_KEY ?? env.PROXY_API_KEY ?? "proxy-local-token",
    codexSettingsAuto: parseBoolean(env.CODEX_SETTINGS_AUTO, false),
    codexConfigPath: clientPaths.codexConfigPath,
    codexProxyURL: env.CODEX_PROXY_URL
      ? normalizeCodexProxyURL(env.CODEX_PROXY_URL)
      : undefined,
    codexProxyAPIKey: env.CODEX_PROXY_API_KEY ?? env.PROXY_API_KEY ?? "proxy-local-token",
    codexUpstreamURL,
    codexUpstreamExplicit: Boolean(env.CODEX_UPSTREAM_URL?.trim()),
    proxyAPIKey: required(env.PROXY_API_KEY, "PROXY_API_KEY"),
    proxyAuthPassthrough: parseBoolean(env.PROXY_AUTH_PASSTHROUGH, false),
    adminToken: required(env.PROXY_ADMIN_TOKEN, "PROXY_ADMIN_TOKEN"),
    maxRequestBytes: parseInteger(env.MAX_REQUEST_BYTES, DEFAULT_MAX_REQUEST_BYTES, "MAX_REQUEST_BYTES"),
    upstreamTimeoutMs: parseInteger(env.UPSTREAM_TIMEOUT_MS, DEFAULT_UPSTREAM_TIMEOUT_MS, "UPSTREAM_TIMEOUT_MS"),
    reviewMode,
    reviewScope: parseReviewScope(prefer(env.REVIEW_SCOPE, env.JUDGE_SCOPE)),
    judgeEnabled,
    judgeProvider,
    judgeBaseURL,
    judgeAPIKey: prefer(env.REVIEW_API_KEY, env.JUDGE_API_KEY),
    judgeModel: prefer(env.REVIEW_MODEL, env.JUDGE_MODEL) ?? defaultJudgeModel(judgeProvider),
    judgeTimeoutMs: parseInteger(
      prefer(env.REVIEW_TIMEOUT_MS, env.JUDGE_TIMEOUT_MS),
      DEFAULT_JUDGE_TIMEOUT_MS,
      preferName(env.REVIEW_TIMEOUT_MS, env.JUDGE_TIMEOUT_MS, "REVIEW_TIMEOUT_MS", "JUDGE_TIMEOUT_MS"),
    ),
    judgeMaxOutputTokens: parseInteger(
      prefer(env.REVIEW_MAX_OUTPUT_TOKENS, env.JUDGE_MAX_OUTPUT_TOKENS),
      DEFAULT_JUDGE_MAX_OUTPUT_TOKENS,
      preferName(
        env.REVIEW_MAX_OUTPUT_TOKENS,
        env.JUDGE_MAX_OUTPUT_TOKENS,
        "REVIEW_MAX_OUTPUT_TOKENS",
        "JUDGE_MAX_OUTPUT_TOKENS",
      ),
    ),
    judgeMaxInputChars: parseInteger(
      prefer(env.REVIEW_MAX_INPUT_CHARS, env.JUDGE_MAX_INPUT_CHARS),
      DEFAULT_JUDGE_MAX_INPUT_CHARS,
      preferName(
        env.REVIEW_MAX_INPUT_CHARS,
        env.JUDGE_MAX_INPUT_CHARS,
        "REVIEW_MAX_INPUT_CHARS",
        "JUDGE_MAX_INPUT_CHARS",
      ),
    ),
    judgeMaxMessages: parseInteger(
      prefer(env.REVIEW_MAX_MESSAGES, env.JUDGE_MAX_MESSAGES),
      DEFAULT_JUDGE_MAX_MESSAGES,
      preferName(
        env.REVIEW_MAX_MESSAGES,
        env.JUDGE_MAX_MESSAGES,
        "REVIEW_MAX_MESSAGES",
        "JUDGE_MAX_MESSAGES",
      ),
    ),
    judgeMaxConcurrent: parseInteger(
      prefer(env.REVIEW_MAX_CONCURRENT, env.JUDGE_MAX_CONCURRENT),
      DEFAULT_JUDGE_MAX_CONCURRENT,
      preferName(
        env.REVIEW_MAX_CONCURRENT,
        env.JUDGE_MAX_CONCURRENT,
        "REVIEW_MAX_CONCURRENT",
        "JUDGE_MAX_CONCURRENT",
      ),
    ),
    judgeMinIntervalMs: parseNonNegativeInteger(
      prefer(env.REVIEW_MIN_INTERVAL_MS, env.JUDGE_MIN_INTERVAL_MS),
      DEFAULT_JUDGE_MIN_INTERVAL_MS,
      preferName(
        env.REVIEW_MIN_INTERVAL_MS,
        env.JUDGE_MIN_INTERVAL_MS,
        "REVIEW_MIN_INTERVAL_MS",
        "JUDGE_MIN_INTERVAL_MS",
      ),
    ),
    judgeQueueSize: parseInteger(
      prefer(env.REVIEW_QUEUE_SIZE, env.JUDGE_QUEUE_SIZE),
      DEFAULT_JUDGE_QUEUE_SIZE,
      preferName(env.REVIEW_QUEUE_SIZE, env.JUDGE_QUEUE_SIZE, "REVIEW_QUEUE_SIZE", "JUDGE_QUEUE_SIZE"),
    ),
    judgeQueueBytes: parseInteger(
      prefer(env.REVIEW_QUEUE_BYTES, env.JUDGE_QUEUE_BYTES),
      DEFAULT_JUDGE_QUEUE_BYTES,
      preferName(env.REVIEW_QUEUE_BYTES, env.JUDGE_QUEUE_BYTES, "REVIEW_QUEUE_BYTES", "JUDGE_QUEUE_BYTES"),
    ),
    judgeMaxRetries: parseNonNegativeInteger(
      prefer(env.REVIEW_MAX_RETRIES, env.JUDGE_MAX_RETRIES),
      DEFAULT_JUDGE_MAX_RETRIES,
      preferName(env.REVIEW_MAX_RETRIES, env.JUDGE_MAX_RETRIES, "REVIEW_MAX_RETRIES", "JUDGE_MAX_RETRIES"),
    ),
    judgeRetryBaseMs: parseNonNegativeInteger(
      prefer(env.REVIEW_RETRY_BASE_MS, env.JUDGE_RETRY_BASE_MS),
      DEFAULT_JUDGE_RETRY_BASE_MS,
      preferName(env.REVIEW_RETRY_BASE_MS, env.JUDGE_RETRY_BASE_MS, "REVIEW_RETRY_BASE_MS", "JUDGE_RETRY_BASE_MS"),
    ),
    judgeFailOpen: parseBoolean(prefer(env.REVIEW_FAIL_OPEN, env.JUDGE_FAIL_OPEN), false),
    disconnectOnBlock: parseBoolean(env.DISCONNECT_ON_BLOCK, false),
    judgePrompt: prefer(env.REVIEW_PROMPT, env.JUDGE_PROMPT),
    judgeAccountID: prefer(env.REVIEW_ACCOUNT_ID, env.JUDGE_ACCOUNT_ID),
    auditPath: env.AUDIT_PATH ?? DEFAULT_AUDIT_PATH,
    auditIncludeBody: parseAuditIncludeBody(env.AUDIT_INCLUDE_BODY),
    auditStdout: parseAuditStdout(env.AUDIT_STDOUT),
    adminConfigPath: env.ADMIN_CONFIG_PATH ?? DEFAULT_ADMIN_CONFIG_PATH,
  }
}

function prefer(value: string | undefined, fallback: string | undefined) {
  const selected = value === undefined || value.trim() === "" ? fallback : value
  return selected === undefined || selected.trim() === "" ? undefined : selected
}

function preferName(value: string | undefined, fallback: string | undefined, valueName: string, fallbackName: string) {
  return value === undefined || value.trim() === ""
    ? fallback === undefined || fallback.trim() === ""
      ? valueName
      : fallbackName
    : valueName
}

function legacyReviewMode(value: string | undefined) {
  return parseBoolean(value, true) ? "llm" : "off"
}

function required(value: string | undefined, name: string) {
  if (value && value.trim()) return value
  throw new Error(`${name} is required`)
}

function normalizeURL(value: string, name: string) {
  const url = parseURL(value, name)
  url.pathname = url.pathname.replace(/\/+$/, "")
  return url.toString().replace(/\/$/, "")
}

function parseURL(value: string, name: string) {
  try {
    const url = new URL(value)
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error()
    return url
  } catch {
    throw new Error(`${name} must be an absolute http(s) URL`)
  }
}

function parseInteger(value: string | undefined, fallback: number, name: string) {
  if (value === undefined || value.trim() === "") return fallback
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`)
  return parsed
}

function parseNonNegativeInteger(value: string | undefined, fallback: number, name: string) {
  if (value === undefined || value.trim() === "") return fallback
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`${name} must be a non-negative integer`)
  return parsed
}

function parseBoolean(value: string | undefined, fallback: boolean) {
  if (value === undefined || value.trim() === "") return fallback
  if (["1", "true", "yes", "on"].includes(value.toLowerCase())) return true
  if (["0", "false", "no", "off"].includes(value.toLowerCase())) return false
  throw new Error(`Invalid boolean value: ${value}`)
}

function parseJudgeProvider(value: string | undefined): JudgeProvider {
  const provider = value?.toLowerCase() ?? "anthropic"
  if (provider === "anthropic" || provider === "openai-responses" || provider === "openai-chat" || provider === "codex")
    return provider
  throw new Error(`Unsupported JUDGE_PROVIDER: ${value}`)
}

function parseReviewMode(value: string | undefined): ReviewMode {
  const mode = value?.toLowerCase() ?? "llm"
  if (mode === "off" || mode === "llm") return mode
  throw new Error(`Unsupported REVIEW_MODE: ${value}`)
}

function parseReviewScope(value: string | undefined): ReviewScope {
  const scope = value?.toLowerCase() ?? DEFAULT_REVIEW_SCOPE
  if (scope === "all" || scope === "api") return scope
  throw new Error(`Unsupported REVIEW_SCOPE: ${value}`)
}

function parseUpstreamAuthMode(value: string | undefined): UpstreamAuthMode {
  const mode = value?.toLowerCase() ?? "anthropic"
  if (mode === "preserve" || mode === "anthropic" || mode === "bearer") return mode
  throw new Error(`Unsupported UPSTREAM_AUTH_MODE: ${value}`)
}

function parseUpstreamSource(value: string | undefined): UpstreamSource {
  const source = value?.toLowerCase() ?? "static"
  if (source === "static" || source === "ccswitch") return source
  throw new Error(`Unsupported UPSTREAM_SOURCE: ${value}`)
}

function parseAuditStdout(value: string | undefined): AuditStdoutMode {
  const mode = value?.toLowerCase() ?? "off"
  if (mode === "off" || mode === "false" || mode === "none") return "off"
  if (mode === "blocked" || mode === "block") return "blocked"
  if (mode === "all" || mode === "true") return "all"
  throw new Error(`Unsupported AUDIT_STDOUT: ${value}`)
}

function parseAuditIncludeBody(value: string | undefined): AuditIncludeBodyMode {
  const mode = value?.toLowerCase() ?? "off"
  if (mode === "off" || mode === "false" || mode === "0" || mode === "no") return "off"
  if (mode === "blocked" || mode === "block") return "blocked"
  if (mode === "all" || mode === "true" || mode === "1" || mode === "yes") return "all"
  throw new Error(`Unsupported AUDIT_INCLUDE_BODY: ${value}`)
}

function defaultCCSwitchSettingsPath(env: Record<string, string | undefined>) {
  const home = env.USERPROFILE ?? env.HOME
  return home ? `${home}/.claude/settings.json` : "./.claude/settings.json"
}

function defaultCodexConfigPath(env: Record<string, string | undefined>) {
  if (env.CODEX_HOME) return `${env.CODEX_HOME}/config.toml`
  const home = env.USERPROFILE ?? env.HOME
  return home ? `${home}/.codex/config.toml` : "./.codex/config.toml"
}

export function clientSettingsPaths(env: Record<string, string | undefined> = Bun.env) {
  const defaultClaudePath = defaultCCSwitchSettingsPath(env)
  return {
    claudeSettingsPath: expandHomePath(
      env.CLAUDE_SETTINGS_PATH ?? env.CCSWITCH_SETTINGS_PATH ?? defaultClaudePath,
      env,
    ),
    codexConfigPath: expandHomePath(env.CODEX_CONFIG_PATH ?? defaultCodexConfigPath(env), env),
  }
}

export function expandHomePath(value: string, env: Record<string, string | undefined> = Bun.env) {
  const home = env.USERPROFILE ?? env.HOME
  if (!home || (!value.startsWith("~/") && !value.startsWith("~\\"))) return value
  return `${home}${value.slice(1)}`
}

export function normalizeCodexProxyURL(value: string) {
  const normalized = normalizeURL(value, "CODEX_PROXY_URL")
  const url = new URL(normalized)
  if (url.search || url.hash || (url.pathname !== "/codex" && !url.pathname.startsWith("/codex/"))) {
    throw new Error("CODEX_PROXY_URL path must start with /codex and must not include a query or fragment")
  }
  return normalized
}

function defaultJudgeBaseURL(provider: JudgeProvider) {
  if (provider === "anthropic") return "https://api.anthropic.com"
  if (provider === "codex") return "https://chatgpt.com/backend-api/codex"
  return "https://api.openai.com"
}

function defaultJudgeModel(provider: JudgeProvider) {
  if (provider === "anthropic") return "claude-haiku-4-5-20251001"
  if (provider === "codex") return "gpt-5.1-codex-mini"
  if (provider === "openai-chat") return "gpt-4o-mini"
  return "gpt-5-mini"
}

export function isProxyEndpoint(value: string, config: Pick<ProxyConfig, "listenHost" | "listenPort">) {
  const url = new URL(value)
  const configuredHost = config.listenHost.replace(/^\[|\]$/g, "").toLowerCase()
  const aliases = new Set([configuredHost])
  if (["127.0.0.1", "localhost", "::1", "0.0.0.0", "::"].includes(configuredHost)) {
    aliases.add("127.0.0.1")
    aliases.add("localhost")
    aliases.add("::1")
  }
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80))
  const targetHost = url.hostname.replace(/^\[|\]$/g, "").toLowerCase()
  return aliases.has(targetHost) && port === config.listenPort
}
