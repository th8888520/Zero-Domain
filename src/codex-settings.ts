import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { mkdir, open, readFile, readdir, rename, unlink } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
import { parse, stringify } from "smol-toml"
import { isProxyEndpoint, normalizeCodexProxyURL, type ProxyConfig } from "./config"

export interface CodexSettingsSession {
  restore(): Promise<void>
  restoreSync(): void
}

interface ManagedProviderSignature {
  id: string
  baseURL: string
  wireAPI: "responses"
  headerName: "x-zero-domain-key"
  headerValue: string
}

interface SettingsBackup {
  version: 1
  originalExists: boolean
  originalBytes?: number[]
  managedBytes: number[]
  managedProvider: ManagedProviderSignature
}

const MANAGED_PROVIDER_BASENAME = "zero-domain"
const PROXY_HEADER = "x-zero-domain-key" as const
const OPENAI_API_UPSTREAM = "https://api.openai.com/v1"
const CHATGPT_CODEX_UPSTREAM = "https://chatgpt.com/backend-api/codex"

export async function recoverCodexSettingsBackup(
  config: Pick<ProxyConfig, "codexConfigPath">,
): Promise<boolean> {
  const configPath = resolve(config.codexConfigPath)
  const backupPath = backupPathFor(configPath)

  // Avoid creating ~/.codex or a lock file when automatic management is disabled
  // and there is no interrupted session to recover.
  if ((await readOptional(backupPath)) === undefined) return false

  const lockPath = lockPathFor(configPath)
  await mkdir(dirname(configPath), { recursive: true })
  await acquireLock(lockPath)
  try {
    return await recoverStaleBackup(configPath, backupPath)
  } finally {
    await releaseLock(lockPath)
  }
}

export async function manageCodexSettings(config: ProxyConfig): Promise<CodexSettingsSession | undefined> {
  if (!config.codexSettingsAuto) {
    await recoverCodexSettingsBackup(config)
    return undefined
  }

  const configPath = resolve(config.codexConfigPath)
  await assertNoProfileProviderOverrides(configPath)
  const lockPath = lockPathFor(configPath)
  const backupPath = backupPathFor(configPath)
  await mkdir(dirname(configPath), { recursive: true })
  await acquireLock(lockPath)

  let createdBackup = false
  try {
    await recoverStaleBackup(configPath, backupPath)
    await assertNoProfileProviderOverrides(configPath)

    const originalBytes = await readOptional(configPath)
    const originalConfig = parseConfig(originalBytes, configPath)
    const builtInOpenAIUpstream = await inferBuiltInOpenAIUpstream(configPath, originalConfig)
    const proxyURL = normalizeCodexProxyURL(
      config.codexProxyURL ?? `http://127.0.0.1:${config.listenPort}/codex`,
    )
    if (config.codexUpstreamURL && isProxyEndpoint(config.codexUpstreamURL, config)) {
      throw new Error("CODEX_UPSTREAM_URL must not point back to this proxy")
    }
    const prepared = prepareManagedConfig(originalConfig, config, proxyURL, configPath, builtInOpenAIUpstream)
    const managedText = `${stringify(prepared.config)}\n`
    const managedBytes = new TextEncoder().encode(managedText)
    const managedProvider: ManagedProviderSignature = {
      id: prepared.providerID,
      baseURL: proxyURL,
      wireAPI: "responses",
      headerName: PROXY_HEADER,
      headerValue: config.codexProxyAPIKey,
    }

    await writeBackup(backupPath, {
      version: 1,
      originalExists: originalBytes !== undefined,
      ...(originalBytes === undefined ? {} : { originalBytes: Array.from(originalBytes) }),
      managedBytes: Array.from(managedBytes),
      managedProvider,
    })
    createdBackup = true
    await writeFileAtomic(configPath, managedBytes)
    createdBackup = false

    if (prepared.capturedUpstreamURL !== undefined) {
      config.codexUpstreamURL = prepared.capturedUpstreamURL
    }

    let restored = false
    return {
      async restore() {
        if (restored) return
        try {
          const currentBytes = await readOptional(configPath)
          if (bytesEqual(currentBytes, managedBytes)) {
            await restoreOriginal(configPath, originalBytes)
            await removeOptional(backupPath)
          } else if (isManagedSnapshot(currentBytes, managedProvider)) {
            await removeManagedProvider(configPath, currentBytes, originalBytes, managedProvider)
            await removeOptional(backupPath)
            console.warn(`[zero-domain] Preserved external Codex config changes while removing the managed provider at ${configPath}`)
          } else if (originalStateMatches(currentBytes, originalBytes)) {
            await removeOptional(backupPath)
          } else {
            const recoveryPath = await preserveConflictOriginal(configPath, originalBytes)
            await removeOptional(backupPath)
            console.warn(
              `[zero-domain] Codex config changed while running; left ${configPath} untouched and preserved the original at ${recoveryPath}`,
            )
          }
        } finally {
          restored = true
          await releaseLock(lockPath)
        }
      },
      restoreSync() {
        if (restored) return
        try {
          const currentBytes = readOptionalSync(configPath)
          if (bytesEqual(currentBytes, managedBytes)) {
            restoreOriginalSync(configPath, originalBytes)
            removeOptionalSync(backupPath)
          } else if (isManagedSnapshot(currentBytes, managedProvider)) {
            removeManagedProviderSync(configPath, currentBytes, originalBytes, managedProvider)
            removeOptionalSync(backupPath)
            console.warn(`[zero-domain] Preserved external Codex config changes while removing the managed provider at ${configPath}`)
          } else if (originalStateMatches(currentBytes, originalBytes)) {
            removeOptionalSync(backupPath)
          } else {
            const recoveryPath = preserveConflictOriginalSync(configPath, originalBytes)
            removeOptionalSync(backupPath)
            console.warn(
              `[zero-domain] Codex config changed while running; left ${configPath} untouched and preserved the original at ${recoveryPath}`,
            )
          }
        } finally {
          restored = true
          releaseLockSync(lockPath)
        }
      },
    }
  } catch (error) {
    if (createdBackup) await removeOptional(backupPath)
    await releaseLock(lockPath)
    throw error
  }
}

function prepareManagedConfig(
  originalConfig: Record<string, unknown>,
  config: ProxyConfig,
  proxyURL: string,
  configPath: string,
  builtInOpenAIUpstream: string,
) {
  const sourceProviderID = activeProviderID(originalConfig, configPath)
  const sourceProviders = providerTables(originalConfig, configPath)
  const sourceProviderValue = sourceProviders[sourceProviderID]
  const sourceProvider = sourceProviderValue === undefined
    ? undefined
    : requireRecord(sourceProviderValue, `Codex model provider ${JSON.stringify(sourceProviderID)} must be a TOML table: ${configPath}`)
  if (sourceProvider?.wire_api !== undefined && sourceProvider.wire_api !== "responses") {
    throw new Error(
      `Codex model provider ${JSON.stringify(sourceProviderID)} must use wire_api = "responses": ${configPath}`,
    )
  }

  let capturedUpstreamURL: string | undefined
  if (sourceProvider !== undefined && !config.codexUpstreamExplicit) {
    const sourceBaseURL = sourceProvider.base_url
    if (sourceBaseURL === undefined) {
      throw new Error(
        `Codex model provider ${JSON.stringify(sourceProviderID)} must define base_url unless CODEX_UPSTREAM_URL is set: ${configPath}`,
      )
    }
    if (typeof sourceBaseURL !== "string" || sourceBaseURL.trim() === "") {
      throw new Error(`Codex model provider ${JSON.stringify(sourceProviderID)} has an invalid base_url: ${configPath}`)
    }
    capturedUpstreamURL = normalizeHTTPURL(sourceBaseURL, `base_url for Codex model provider ${sourceProviderID}`)
    if (isProxyEndpoint(capturedUpstreamURL, config)) {
      throw new Error(
        `Codex model provider ${JSON.stringify(sourceProviderID)} points back to this proxy and would create a forwarding loop: ${capturedUpstreamURL}`,
      )
    }
  } else if (sourceProvider === undefined && !config.codexUpstreamExplicit) {
    if (sourceProviderID !== "openai") {
      throw new Error(
        `Codex model provider ${JSON.stringify(sourceProviderID)} must define a model_providers table or CODEX_UPSTREAM_URL: ${configPath}`,
      )
    }
    capturedUpstreamURL = builtInOpenAIUpstream
  }

  const managedConfig = cloneRecord(originalConfig)
  const managedProviders = cloneRecord(sourceProviders)
  const providerID = uniqueProviderID(sourceProviderID, managedProviders)
  const existingHeaders = sourceProvider?.http_headers
  if (existingHeaders !== undefined && !isRecord(existingHeaders)) {
    throw new Error(`Codex model provider ${JSON.stringify(sourceProviderID)} has a non-table http_headers value: ${configPath}`)
  }
  const httpHeaders = existingHeaders === undefined ? {} : cloneRecord(existingHeaders)
  httpHeaders[PROXY_HEADER] = config.codexProxyAPIKey

  managedProviders[providerID] = sourceProvider === undefined
    ? {
        name: "OpenAI through zero-domain",
        base_url: proxyURL,
        wire_api: "responses",
        requires_openai_auth: true,
        http_headers: httpHeaders,
      }
    : {
        ...cloneRecord(sourceProvider),
        base_url: proxyURL,
        wire_api: "responses",
        http_headers: httpHeaders,
      }
  managedConfig.model_providers = managedProviders
  managedConfig.model_provider = providerID

  return { config: managedConfig, providerID, capturedUpstreamURL }
}

async function inferBuiltInOpenAIUpstream(configPath: string, config: Record<string, unknown>) {
  const forcedLoginMethod = stringValue(config.forced_login_method)?.toLowerCase()
  if (forcedLoginMethod === "chatgpt") return CHATGPT_CODEX_UPSTREAM
  if (forcedLoginMethod === "api" || forcedLoginMethod === "api_key") return OPENAI_API_UPSTREAM

  const authBytes = await readOptional(join(dirname(configPath), "auth.json"))
  if (authBytes === undefined) return OPENAI_API_UPSTREAM
  try {
    const auth = JSON.parse(new TextDecoder().decode(authBytes)) as unknown
    if (!isRecord(auth)) return OPENAI_API_UPSTREAM
    const authMode = stringValue(auth.auth_mode)?.toLowerCase()
    if (authMode?.includes("chatgpt") || isRecord(auth.tokens)) return CHATGPT_CODEX_UPSTREAM
  } catch {
    // A malformed auth file is reported by Codex itself; use the API endpoint as a neutral fallback.
  }
  return OPENAI_API_UPSTREAM
}

async function recoverStaleBackup(configPath: string, backupPath: string) {
  const backup = await readBackup(backupPath)
  if (!backup) return false

  const originalBytes = backup.originalExists ? Uint8Array.from(backup.originalBytes ?? []) : undefined
  const currentBytes = await readOptional(configPath)
  if (bytesEqual(currentBytes, Uint8Array.from(backup.managedBytes))) {
    await restoreOriginal(configPath, originalBytes)
    await removeOptional(backupPath)
    console.warn(`[zero-domain] Restored a stale Codex config backup at ${configPath}`)
    return true
  }

  if (isManagedSnapshot(currentBytes, backup.managedProvider)) {
    await removeManagedProvider(configPath, currentBytes, originalBytes, backup.managedProvider)
    await removeOptional(backupPath)
    console.warn(
      `[zero-domain] Recovered a stale Codex config at ${configPath} while preserving non-managed changes`,
    )
    return true
  }

  if (originalStateMatches(currentBytes, originalBytes)) {
    await removeOptional(backupPath)
    return true
  }

  const recoveryPath = await preserveConflictOriginal(configPath, originalBytes)
  await removeOptional(backupPath)
  console.warn(
    `[zero-domain] A stale Codex config was externally changed; left ${configPath} untouched and preserved the original at ${recoveryPath}`,
  )
  return true
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
    if (!isByteArray(value.managedBytes) || !isRecord(value.managedProvider)) throw new Error()
    if (value.originalExists && !isByteArray(value.originalBytes)) throw new Error()

    const provider = value.managedProvider
    if (
      typeof provider.id !== "string" ||
      typeof provider.baseURL !== "string" ||
      provider.wireAPI !== "responses" ||
      provider.headerName !== PROXY_HEADER ||
      typeof provider.headerValue !== "string"
    ) throw new Error()

    return {
      version: 1,
      originalExists: value.originalExists,
      ...(value.originalExists ? { originalBytes: value.originalBytes as number[] } : {}),
      managedBytes: value.managedBytes as number[],
      managedProvider: {
        id: provider.id,
        baseURL: provider.baseURL,
        wireAPI: "responses",
        headerName: PROXY_HEADER,
        headerValue: provider.headerValue,
      },
    }
  } catch {
    return undefined
  }
}

function isManagedSnapshot(bytes: Uint8Array | undefined, signature: ManagedProviderSignature) {
  if (bytes === undefined) return false
  try {
    const value = parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
    if (!isRecord(value.model_providers)) return false
    const provider = value.model_providers[signature.id]
    if (!isRecord(provider) || !isRecord(provider.http_headers)) return false
    return (
      provider.base_url === signature.baseURL &&
      provider.wire_api === signature.wireAPI &&
      provider.http_headers[signature.headerName] === signature.headerValue
    )
  } catch {
    return false
  }
}

async function removeManagedProvider(
  configPath: string,
  currentBytes: Uint8Array | undefined,
  originalBytes: Uint8Array | undefined,
  signature: ManagedProviderSignature,
) {
  await writeFileAtomic(configPath, configWithoutManagedProvider(configPath, currentBytes, originalBytes, signature))
}

function removeManagedProviderSync(
  configPath: string,
  currentBytes: Uint8Array | undefined,
  originalBytes: Uint8Array | undefined,
  signature: ManagedProviderSignature,
) {
  writeFileAtomicSync(configPath, configWithoutManagedProvider(configPath, currentBytes, originalBytes, signature))
}

function configWithoutManagedProvider(
  configPath: string,
  currentBytes: Uint8Array | undefined,
  originalBytes: Uint8Array | undefined,
  signature: ManagedProviderSignature,
) {
  if (currentBytes === undefined) throw new Error(`Managed Codex config disappeared before it could be restored: ${configPath}`)

  const currentConfig = parseConfig(currentBytes, configPath)
  const originalConfig = parseConfig(originalBytes, configPath)
  const originalProviderID = activeProviderID(originalConfig, configPath)
  providerTables(originalConfig, configPath)

  const cleanedConfig = cloneRecord(currentConfig)
  const cleanedProviders = cloneRecord(providerTables(currentConfig, configPath))
  if (!Object.prototype.hasOwnProperty.call(cleanedProviders, signature.id)) {
    throw new Error(`Managed Codex provider ${JSON.stringify(signature.id)} is missing from ${configPath}`)
  }
  delete cleanedProviders[signature.id]

  if (
    Object.keys(cleanedProviders).length === 0 &&
    !Object.prototype.hasOwnProperty.call(originalConfig, "model_providers")
  ) {
    delete cleanedConfig.model_providers
  } else {
    cleanedConfig.model_providers = cleanedProviders
  }

  if (currentConfig.model_provider === signature.id) {
    if (Object.prototype.hasOwnProperty.call(originalConfig, "model_provider")) {
      cleanedConfig.model_provider = originalProviderID
    } else {
      delete cleanedConfig.model_provider
    }
  }

  return new TextEncoder().encode(`${stringify(cleanedConfig)}\n`)
}

function parseConfig(bytes: Uint8Array | undefined, path: string): Record<string, unknown> {
  if (bytes === undefined) return {}
  try {
    return parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
  } catch (error) {
    const detail = error instanceof Error && error.message ? ` (${error.message})` : ""
    throw new Error(`Codex config must contain valid TOML: ${path}${detail}`)
  }
}

async function assertNoProfileProviderOverrides(configPath: string) {
  const directory = dirname(configPath)
  let entries
  try {
    entries = await readdir(directory, { withFileTypes: true })
  } catch (error) {
    if (errorCode(error) === "ENOENT") return
    throw error
  }

  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.name.toLowerCase().endsWith(".config.toml")) continue
    if (!entry.isFile() && !entry.isSymbolicLink()) continue

    const profilePath = resolve(directory, entry.name)
    if (samePath(profilePath, configPath)) continue
    const profileBytes = await readOptional(profilePath)
    if (profileBytes === undefined) continue
    const profileConfig = parseConfig(profileBytes, profilePath)
    if (Object.prototype.hasOwnProperty.call(profileConfig, "model_provider")) {
      throw new Error(
        `Codex profile config defines a top-level model_provider that would bypass proxy management: ${profilePath}`,
      )
    }
  }
}

function samePath(left: string, right: string) {
  return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right
}

function activeProviderID(config: Record<string, unknown>, path: string) {
  const value = config.model_provider
  if (value === undefined) return "openai"
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Codex config model_provider must be a non-empty string: ${path}`)
  }
  return value
}

function providerTables(config: Record<string, unknown>, path: string) {
  const value = config.model_providers
  if (value === undefined) return {}
  return requireRecord(value, `Codex config model_providers must be a TOML table: ${path}`)
}

function uniqueProviderID(sourceProviderID: string, providers: Record<string, unknown>) {
  let candidate = MANAGED_PROVIDER_BASENAME
  let suffix = 2
  while (candidate === sourceProviderID || Object.prototype.hasOwnProperty.call(providers, candidate)) {
    candidate = `${MANAGED_PROVIDER_BASENAME}-${suffix}`
    suffix += 1
  }
  return candidate
}

function normalizeHTTPURL(value: string, name: string) {
  try {
    const url = new URL(value)
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error()
    url.pathname = url.pathname.replace(/\/+$/, "")
    return url.toString().replace(/\/$/, "")
  } catch {
    throw new Error(`${name} must be an absolute http(s) URL`)
  }
}

async function preserveConflictOriginal(configPath: string, originalBytes: Uint8Array | undefined) {
  const path = await availableConflictPath(configPath)
  const data = originalBytes ?? `${JSON.stringify({ originalExists: false })}\n`
  await writeFileAtomic(path, data)
  return path
}

function preserveConflictOriginalSync(configPath: string, originalBytes: Uint8Array | undefined) {
  const path = availableConflictPathSync(configPath)
  const data = originalBytes ?? `${JSON.stringify({ originalExists: false })}\n`
  writeFileAtomicSync(path, data)
  return path
}

async function availableConflictPath(configPath: string) {
  const base = conflictPathFor(configPath)
  for (let suffix = 0; ; suffix += 1) {
    const candidate = suffix === 0 ? base : `${base}.${suffix}`
    if ((await readOptional(candidate)) === undefined) return candidate
  }
}

function availableConflictPathSync(configPath: string) {
  const base = conflictPathFor(configPath)
  for (let suffix = 0; ; suffix += 1) {
    const candidate = suffix === 0 ? base : `${base}.${suffix}`
    if (!existsSync(candidate)) return candidate
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
    const handle = await open(tempPath, "wx", 0o600)
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
  let descriptor: number | undefined
  try {
    descriptor = openSync(tempPath, "wx", 0o600)
    writeFileSync(descriptor, data)
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined
    renameSync(tempPath, path)
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
    removeOptionalSync(tempPath)
  }
}

function temporaryPath(path: string) {
  return `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

async function acquireLock(path: string): Promise<void> {
  try {
    const handle = await open(path, "wx", 0o600)
    try {
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`)
      await handle.sync()
    } finally {
      await handle.close()
    }
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error
    const ownerPID = await readLockPID(path)
    if (ownerPID === undefined || isProcessAlive(ownerPID)) {
      throw new Error(`Codex config is already managed: ${path}`)
    }
    await removeOptional(path)
    await acquireLock(path)
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
    return errorCode(error) === "EPERM"
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

function backupPathFor(configPath: string) {
  return `${configPath}.zero-domain.backup`
}

function lockPathFor(configPath: string) {
  return `${configPath}.zero-domain.lock`
}

function conflictPathFor(configPath: string) {
  return `${configPath}.zero-domain.conflict-original`
}

function originalStateMatches(current: Uint8Array | undefined, original: Uint8Array | undefined) {
  return current === undefined ? original === undefined : original !== undefined && bytesEqual(current, original)
}

function bytesEqual(left: Uint8Array | undefined, right: Uint8Array) {
  if (left === undefined || left.byteLength !== right.byteLength) return false
  return left.every((value, index) => value === right[index])
}

function isByteArray(value: unknown): value is number[] {
  return Array.isArray(value) && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
}

function cloneRecord(value: Record<string, unknown>) {
  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) result[key] = cloneValue(item)
  return result
}

function cloneValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(cloneValue)
  if (isRecord(value) && !(value instanceof Date)) return cloneRecord(value)
  return value
}

function requireRecord(value: unknown, message: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(message)
  return value
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : undefined
}

function errorCode(error: unknown) {
  return isRecord(error) && typeof error.code === "string" ? error.code : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
