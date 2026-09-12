import { open, mkdir, readFile, rename, unlink } from "node:fs/promises"
import { readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { isProxyEndpoint, type ProxyConfig } from "./config"

export interface ClaudeSettingsSession {
  restore(): Promise<void>
  restoreSync(): void
}

interface ManagedEnvironment {
  ANTHROPIC_BASE_URL: string
  ANTHROPIC_API_KEY: string
  ANTHROPIC_AUTH_TOKEN?: string
}

interface SettingsBackup {
  version: 1
  originalExists: boolean
  originalBytes?: number[]
  managedEnvironment: ManagedEnvironment
}

export async function recoverClaudeSettingsBackup(
  config: Pick<ProxyConfig, "claudeSettingsPath">,
): Promise<boolean> {
  const settingsPath = resolve(config.claudeSettingsPath)
  const lockPath = `${settingsPath}.zero-domain.lock`
  const backupPath = `${settingsPath}.zero-domain.backup`
  if ((await readOptional(backupPath)) === undefined) return false
  await mkdir(dirname(settingsPath), { recursive: true })
  await acquireLock(lockPath)
  try {
    await recoverStaleBackup(settingsPath, backupPath)
    return true
  } finally {
    await releaseLock(lockPath)
  }
}

export async function manageClaudeSettings(config: ProxyConfig): Promise<ClaudeSettingsSession | undefined> {
  if (!config.claudeSettingsAuto) return undefined

  const settingsPath = resolve(config.claudeSettingsPath)
  const lockPath = `${settingsPath}.zero-domain.lock`
  const backupPath = `${settingsPath}.zero-domain.backup`
  await mkdir(dirname(settingsPath), { recursive: true })
  await acquireLock(lockPath)

  try {
    await recoverStaleBackup(settingsPath, backupPath)
    const originalBytes = await readOptional(settingsPath)
    const originalSettings = parseSettings(originalBytes, settingsPath)
    captureCCSwitchFallback(config, originalSettings, settingsPath)

    const proxyURL = config.claudeProxyURL ?? `http://127.0.0.1:${config.listenPort}`
    const managedEnvironment: ManagedEnvironment = {
      ANTHROPIC_BASE_URL: proxyURL,
      ANTHROPIC_API_KEY: config.claudeProxyAPIKey,
    }
    const environment = isRecord(originalSettings.env) ? { ...originalSettings.env } : {}
    delete environment.ANTHROPIC_AUTH_TOKEN
    Object.assign(environment, managedEnvironment)
    const managedBytes = new TextEncoder().encode(
      `${JSON.stringify({ ...originalSettings, env: environment }, null, 2)}\n`,
    )
    await writeBackup(backupPath, {
      version: 1,
      originalExists: originalBytes !== undefined,
      ...(originalBytes === undefined ? {} : { originalBytes: Array.from(originalBytes) }),
      managedEnvironment,
    })
    await writeFileAtomic(settingsPath, managedBytes)

    let restored = false
    return {
      async restore() {
        if (restored) return
        try {
          const currentBytes = await readOptional(settingsPath)
          if (bytesEqual(currentBytes, managedBytes) || isManagedSnapshot(currentBytes, managedEnvironment)) {
            await restoreOriginal(settingsPath, originalBytes)
            await removeOptional(backupPath)
          } else {
            console.warn(`[zero-domain] Claude settings changed while running; leaving ${settingsPath} untouched`)
            await removeOptional(backupPath)
          }
        } finally {
          restored = true
          await releaseLock(lockPath)
        }
      },
      restoreSync() {
        if (restored) return
        try {
          const currentBytes = readOptionalSync(settingsPath)
          if (bytesEqual(currentBytes, managedBytes) || isManagedSnapshot(currentBytes, managedEnvironment)) {
            restoreOriginalSync(settingsPath, originalBytes)
            removeOptionalSync(backupPath)
          } else {
            console.warn(`[zero-domain] Claude settings changed while running; leaving ${settingsPath} untouched`)
            removeOptionalSync(backupPath)
          }
        } finally {
          restored = true
          releaseLockSync(lockPath)
        }
      },
    }
  } catch (error) {
    await removeOptional(backupPath)
    await releaseLock(lockPath)
    throw error
  }
}

async function recoverStaleBackup(settingsPath: string, backupPath: string) {
  const backup = await readBackup(backupPath)
  if (!backup) return

  const currentBytes = await readOptional(settingsPath)
  if (isManagedSnapshot(currentBytes, backup.managedEnvironment)) {
    await restoreOriginal(settingsPath, backup.originalExists ? Uint8Array.from(backup.originalBytes ?? []) : undefined)
    console.warn(`[zero-domain] Restored a stale CCSwitch settings backup at ${settingsPath}`)
  }
  await removeOptional(backupPath)
}

async function writeBackup(path: string, backup: SettingsBackup) {
  await writeFileAtomic(path, `${JSON.stringify(backup)}\n`)
}

async function readBackup(path: string): Promise<SettingsBackup | undefined> {
  const bytes = await readOptional(path)
  if (bytes === undefined) return undefined

  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as unknown
    if (!isRecord(value) || value.version !== 1 || typeof value.originalExists !== "boolean") throw new Error()
    if (!isRecord(value.managedEnvironment)) throw new Error()
    const managedEnvironment = value.managedEnvironment
    if (
      typeof managedEnvironment.ANTHROPIC_BASE_URL !== "string" ||
      typeof managedEnvironment.ANTHROPIC_API_KEY !== "string" ||
      (managedEnvironment.ANTHROPIC_AUTH_TOKEN !== undefined &&
        typeof managedEnvironment.ANTHROPIC_AUTH_TOKEN !== "string")
    ) throw new Error()

    const originalBytes = value.originalBytes
    if (
      value.originalExists &&
      (!Array.isArray(originalBytes) || originalBytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255))
    ) throw new Error()

    return {
      version: 1,
      originalExists: value.originalExists,
      ...(value.originalExists ? { originalBytes: originalBytes as number[] } : {}),
      managedEnvironment: {
        ANTHROPIC_BASE_URL: managedEnvironment.ANTHROPIC_BASE_URL,
        ANTHROPIC_API_KEY: managedEnvironment.ANTHROPIC_API_KEY,
        ...(managedEnvironment.ANTHROPIC_AUTH_TOKEN === undefined
          ? {}
          : { ANTHROPIC_AUTH_TOKEN: managedEnvironment.ANTHROPIC_AUTH_TOKEN }),
      },
    }
  } catch {
    await removeOptional(path)
    return undefined
  }
}

async function restoreOriginal(path: string, originalBytes: Uint8Array | undefined) {
  if (originalBytes === undefined) await removeOptional(path)
  else await writeFileAtomic(path, originalBytes)
}

function restoreOriginalSync(path: string, originalBytes: Uint8Array | undefined) {
  if (originalBytes === undefined) removeOptionalSync(path)
  else writeFileAtomicSync(path, originalBytes)
}

async function writeFileAtomic(path: string, data: Uint8Array | string) {
  const tempPath = temporaryPath(path)
  try {
    const handle = await open(tempPath, "w")
    try {
      await handle.writeFile(data)
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(tempPath, path)
  } finally {
    await removeOptional(tempPath)
  }
}

function writeFileAtomicSync(path: string, data: Uint8Array | string) {
  const tempPath = temporaryPath(path)
  try {
    writeFileSync(tempPath, data)
    renameSync(tempPath, path)
  } finally {
    removeOptionalSync(tempPath)
  }
}

function temporaryPath(path: string) {
  return `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

async function acquireLock(path: string) {
  try {
    const handle = await open(path, "wx")
    try {
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`)
    } finally {
      await handle.close()
    }
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error
    const ownerPID = await readLockPID(path)
    if (ownerPID === undefined || isProcessAlive(ownerPID)) throw new Error(`Claude settings are already managed: ${path}`)
    await removeOptional(path)
    return acquireLock(path)
  }
}

async function readLockPID(path: string) {
  try {
    const value = JSON.parse(new TextDecoder().decode(await readFile(path))) as unknown
    return isRecord(value) && typeof value.pid === "number" ? value.pid : undefined
  } catch {
    return undefined
  }
}

function isProcessAlive(pid: number) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const code = errorCode(error)
    // EPERM: process exists but no permission; ESRCH: no such process
    return code === "EPERM"
  }
}

async function releaseLock(path: string) {
  try {
    await unlink(path)
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error
  }
}

function releaseLockSync(path: string) {
  try {
    unlinkSync(path)
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error
  }
}

async function readOptional(path: string) {
  try {
    return new Uint8Array(await readFile(path))
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined
    throw error
  }
}

function readOptionalSync(path: string) {
  try {
    return new Uint8Array(readFileSync(path))
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined
    throw error
  }
}

async function removeOptional(path: string) {
  try {
    await unlink(path)
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error
  }
}

function removeOptionalSync(path: string) {
  try {
    unlinkSync(path)
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error
  }
}

function parseSettings(bytes: Uint8Array | undefined, path: string) {
  if (bytes === undefined) return {}
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new Error(`Claude settings must contain valid JSON: ${path}`)
  }
  if (!isRecord(value)) throw new Error(`Claude settings must contain a JSON object: ${path}`)
  return value
}

function isManagedSnapshot(bytes: Uint8Array | undefined, managedEnvironment: ManagedEnvironment) {
  if (bytes === undefined) return false
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as unknown
    if (!isRecord(value) || !isRecord(value.env)) return false
    return (
      value.env.ANTHROPIC_BASE_URL === managedEnvironment.ANTHROPIC_BASE_URL &&
      value.env.ANTHROPIC_API_KEY === managedEnvironment.ANTHROPIC_API_KEY &&
      (managedEnvironment.ANTHROPIC_AUTH_TOKEN === undefined
        ? !Object.prototype.hasOwnProperty.call(value.env, "ANTHROPIC_AUTH_TOKEN")
        : value.env.ANTHROPIC_AUTH_TOKEN === managedEnvironment.ANTHROPIC_AUTH_TOKEN)
    )
  } catch {
    return false
  }
}

function captureCCSwitchFallback(config: ProxyConfig, settings: Record<string, unknown>, settingsPath: string) {
  if (config.upstreamSource !== "ccswitch" || resolve(config.ccswitchSettingsPath) !== settingsPath) return
  const environment = isRecord(settings.env) ? settings.env : undefined
  const url = parseURL(environment?.ANTHROPIC_BASE_URL)
  if (!url || isProxyEndpoint(url, config)) return

  const authToken = stringValue(environment?.ANTHROPIC_AUTH_TOKEN)
  const apiKey = stringValue(environment?.ANTHROPIC_API_KEY)
  // 仅在 settings 自带凭证时才捕获；禁止只改 URL 却沿用进程内旧 Key
  if (!authToken && !apiKey) return
  config.upstreamURL = url
  config.upstreamAPIKey = authToken ?? apiKey
  config.upstreamAuthMode = authToken ? "bearer" : "anthropic"
}

function parseURL(value: unknown) {
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

function bytesEqual(left: Uint8Array | undefined, right: Uint8Array) {
  if (left === undefined || left.byteLength !== right.byteLength) return false
  return left.every((value, index) => value === right[index])
}

function errorCode(error: unknown) {
  return isRecord(error) && typeof error.code === "string" ? error.code : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
