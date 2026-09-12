import { mkdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises"
import { dirname } from "node:path"

export const DEFAULT_ADMIN_CONFIG_PATH = "./data/zero-domain.config.json"

export type ConfigOverrides = Record<string, string>

/** 密钥轮换时间戳（与 overrides 分文件，避免污染 env） */
export type SecretRotationMeta = {
  rotatedAt: Record<string, string>
}

/** 按路径串行化读写，避免并发 PUT 丢更新 */
const configWriteQueues = new Map<string, Promise<unknown>>()

const SECRET_KEY_PATTERN = /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i

export async function readConfigOverrides(path: string): Promise<ConfigOverrides> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown
    if (!isRecord(parsed)) return {}
    return Object.fromEntries(
      Object.entries(parsed).flatMap(([key, value]) => {
        if (typeof value === "string") return [[key, value]]
        if (typeof value === "number" || typeof value === "boolean") return [[key, String(value)]]
        return []
      }),
    )
  } catch (error) {
    if (isRecord(error) && error.code === "ENOENT") return {}
    console.error(`[zero-domain] failed to read config overrides ${path}: ${error instanceof Error ? error.message : String(error)}`)
    return {}
  }
}

export async function writeConfigOverrides(path: string, overrides: ConfigOverrides, options?: { merge?: boolean }) {
  return enqueueConfigWrite(path, async () => {
    await mkdir(dirname(path), { recursive: true })
    const merge = options?.merge !== false
    const next = merge ? { ...(await readConfigOverrides(path)), ...overrides } : { ...overrides }
    const temporary = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
    try {
      await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, "utf8")
      await rename(temporary, path)
    } finally {
      await unlink(temporary).catch((error) => {
        if (!isRecord(error) || error.code !== "ENOENT") throw error
      })
    }
  })
}

export function secretMetaPath(configPath: string) {
  return `${configPath}.secrets-meta.json`
}

export async function readSecretRotationMeta(configPath: string): Promise<SecretRotationMeta> {
  try {
    const parsed = JSON.parse(await readFile(secretMetaPath(configPath), "utf8")) as unknown
    if (!isRecord(parsed) || !isRecord(parsed.rotatedAt)) return { rotatedAt: {} }
    const rotatedAt: Record<string, string> = {}
    for (const [key, value] of Object.entries(parsed.rotatedAt)) {
      if (typeof value === "string" && value.trim()) rotatedAt[key] = value
    }
    return { rotatedAt }
  } catch (error) {
    if (isRecord(error) && error.code === "ENOENT") return { rotatedAt: {} }
    return { rotatedAt: {} }
  }
}

export async function markSecretsRotated(configPath: string, keys: string[]) {
  const secretKeys = keys.filter((key) => SECRET_KEY_PATTERN.test(key))
  if (secretKeys.length === 0) return
  const current = await readSecretRotationMeta(configPath)
  const now = new Date().toISOString()
  for (const key of secretKeys) current.rotatedAt[key] = now
  const metaPath = secretMetaPath(configPath)
  await mkdir(dirname(metaPath), { recursive: true })
  const temporary = `${metaPath}.tmp-${process.pid}-${Date.now()}`
  try {
    await writeFile(temporary, `${JSON.stringify(current, null, 2)}\n`, "utf8")
    await rename(temporary, metaPath)
  } finally {
    await unlink(temporary).catch((error) => {
      if (!isRecord(error) || error.code !== "ENOENT") throw error
    })
  }
}

export async function buildSecretsReminder(configPath: string, liveSecrets: { key: string; configured: boolean; suffix?: string }[]) {
  const overrides = await readConfigOverrides(configPath)
  const meta = await readSecretRotationMeta(configPath)
  const persistedSecretKeys = Object.keys(overrides).filter((key) => SECRET_KEY_PATTERN.test(key)).sort()
  let mtimeIso: string | undefined
  let ageDays: number | undefined
  try {
    const info = await stat(configPath)
    mtimeIso = new Date(info.mtimeMs).toISOString()
    ageDays = Math.floor((Date.now() - info.mtimeMs) / (24 * 60 * 60 * 1000))
  } catch {
    /* 文件可能尚不存在 */
  }

  const messages: string[] = []
  if (persistedSecretKeys.length > 0) {
    messages.push(`持久化配置含密钥字段：${persistedSecretKeys.join(", ")}（路径 ${configPath}，勿提交 git）`)
  }
  for (const item of liveSecrets) {
    if (!item.configured) continue
    const rotated = meta.rotatedAt[item.key]
    if (rotated) {
      const days = Math.floor((Date.now() - Date.parse(rotated)) / (24 * 60 * 60 * 1000))
      if (Number.isFinite(days) && days >= 30) {
        messages.push(`${item.key} 距上次轮换约 ${days} 天，建议更换`)
      }
    } else if (persistedSecretKeys.includes(item.key) && (ageDays === undefined || ageDays >= 30)) {
      messages.push(`${item.key} 已写入持久化配置，建议定期轮换（末四位 ${item.suffix ?? "****"}）`)
    } else if (persistedSecretKeys.includes(item.key)) {
      messages.push(`${item.key} 已持久化（末四位 ${item.suffix ?? "****"}），可随时在配置中轮换`)
    }
  }
  if (messages.length === 0 && liveSecrets.some((item) => item.configured)) {
    messages.push("审查/代理密钥已配置。密钥写入 data/ 持久化文件后请定期轮换，并确认 data/ 在 .gitignore 中")
  }

  return {
    configPath,
    configMtime: mtimeIso,
    configAgeDays: ageDays,
    persistedSecretKeys,
    rotatedAt: meta.rotatedAt,
    recommendRotate: messages.some((message) => message.includes("建议")),
    messages,
  }
}

async function enqueueConfigWrite<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const previous = configWriteQueues.get(path) ?? Promise.resolve()
  const next = previous.then(operation, operation)
  const settled = next.then(
    () => undefined,
    () => undefined,
  )
  configWriteQueues.set(path, settled)
  void settled.then(() => {
    if (configWriteQueues.get(path) === settled) configWriteQueues.delete(path)
  })
  return next
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
