import { isProxyEndpoint, type ProxyConfig, type UpstreamAuthMode } from "./config"

export type UpstreamResolvedFrom = "static" | "ccswitch" | "fallback"

export type ResolvedUpstream = {
  url: string
  apiKey: string | undefined
  authMode: UpstreamAuthMode
  resolvedFrom: UpstreamResolvedFrom
}

type CacheEntry = {
  mtimeMs: number
  expiresAt: number
  value: ResolvedUpstream
}

const CACHE_TTL_MS = 2_000
const upstreamCache = new Map<string, CacheEntry>()

export async function resolveUpstream(config: ProxyConfig): Promise<ResolvedUpstream> {
  if (config.upstreamSource !== "ccswitch") {
    return {
      url: config.upstreamURL,
      apiKey: config.upstreamAPIKey,
      authMode: config.upstreamAuthMode,
      resolvedFrom: "static",
    }
  }

  const cacheKey = config.ccswitchSettingsPath
  const cached = upstreamCache.get(cacheKey)
  const now = Date.now()
  const mtimeMs = await settingsMtimeMs(config.ccswitchSettingsPath)
  if (cached && cached.expiresAt > now && cached.mtimeMs === mtimeMs) {
    return cached.value
  }

  const fallback: ResolvedUpstream = {
    url: config.upstreamURL,
    apiKey: config.upstreamAPIKey,
    authMode: config.upstreamAuthMode,
    resolvedFrom: "fallback",
  }

  const settings = await readCCSwitchSettings(config.ccswitchSettingsPath)
  const environment = settings && isRecord(settings.env) ? settings.env : undefined
  const url = parseUpstreamURL(environment?.ANTHROPIC_BASE_URL)
  if (!url || isProxyEndpoint(url, config)) {
    upstreamCache.set(cacheKey, { mtimeMs, expiresAt: now + CACHE_TTL_MS, value: fallback })
    return fallback
  }

  const authToken = stringValue(environment?.ANTHROPIC_AUTH_TOKEN)
  const apiKey = stringValue(environment?.ANTHROPIC_API_KEY)
  // 禁止「ccswitch 外部 URL + 本地 fallback Key」混绑：否则密钥会打到 settings 里的任意上游
  if (!authToken && !apiKey) {
    upstreamCache.set(cacheKey, { mtimeMs, expiresAt: now + CACHE_TTL_MS, value: fallback })
    return fallback
  }
  const resolved: ResolvedUpstream = {
    url,
    apiKey: authToken ?? apiKey,
    authMode: authToken ? "bearer" : "anthropic",
    resolvedFrom: "ccswitch",
  }
  upstreamCache.set(cacheKey, { mtimeMs, expiresAt: now + CACHE_TTL_MS, value: resolved })
  return resolved
}

export function invalidateUpstreamCache(path?: string) {
  if (!path) {
    upstreamCache.clear()
    return
  }
  upstreamCache.delete(path)
}

async function readCCSwitchSettings(path: string) {
  try {
    const value = (await Bun.file(path).json()) as unknown
    return isRecord(value) ? value : undefined
  } catch {
    return undefined
  }
}

async function settingsMtimeMs(path: string) {
  try {
    return (await Bun.file(path).stat()).mtimeMs
  } catch {
    return -1
  }
}

function parseUpstreamURL(value: unknown) {
  const raw = stringValue(value)
  if (!raw) return undefined
  try {
    const url = new URL(raw)
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined
    url.pathname = url.pathname.replace(/\/+$/, "")
    return url.toString().replace(/\/$/, "")
  } catch {
    return undefined
  }
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
