import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }
const integer = (value, label, min, max) => { if (!Number.isSafeInteger(value) || value < min || value > max) throw fail('INVALID_MANIFEST', `${label} invalid`) }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|token|raw|body|content|log|prompt|chat)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function uniqueHashes(values, label, min = 1, max = 1000) {
  if (!Array.isArray(values) || values.length < min || values.length > max) throw fail('INVALID_MANIFEST', `${label} invalid`)
  const set = new Set(); for (const [index, value] of values.entries()) { hash(value, `${label}[${index}]`); if (set.has(value)) throw fail('INVALID_MANIFEST', `duplicate ${label}`); set.add(value) } return set
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest); boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const session = manifest.session || {}
  for (const key of ['sessionIdHash', 'emergencyRequestSha256', 'approvalReceiptSha256', 'principalBindingSha256', 'incidentSha256', 'policySha256']) hash(session[key], `session.${key}`)
  const requestedMs = timestamp(session.requestedAt, 'session.requestedAt'); const activatedMs = timestamp(session.activatedAt, 'session.activatedAt'); const expiresMs = timestamp(session.expiresAt, 'session.expiresAt'); const terminatedMs = timestamp(session.terminatedAt, 'session.terminatedAt')
  const policy = manifest.policy || {}
  integer(policy.maxSessionMs, 'policy.maxSessionMs', 1000, 7 * 86400000); integer(policy.maxEvidenceAgeMs, 'policy.maxEvidenceAgeMs', 1000, 365 * 86400000); integer(policy.minDistinctObservers, 'policy.minDistinctObservers', 1, 100)
  const allowedActions = uniqueHashes(policy.allowedActionIdHashes, 'allowedActionIdHashes'); const allowedResources = uniqueHashes(policy.allowedResourceHashes, 'allowedResourceHashes')
  if (!Array.isArray(manifest.actions) || !manifest.actions.length || manifest.actions.length > 10000) throw fail('INVALID_MANIFEST', 'actions invalid')
  const actionReceipts = new Set()
  const actions = manifest.actions.map((action, index) => {
    for (const key of ['actionReceiptSha256', 'sessionIdHash', 'principalBindingSha256', 'actionIdHash', 'resourceHash', 'observerHash']) hash(action?.[key], `actions[${index}].${key}`)
    if (action.sequence !== index + 1) throw fail('INVALID_MANIFEST', 'action sequence must be contiguous')
    if (actionReceipts.has(action.actionReceiptSha256)) throw fail('INVALID_MANIFEST', 'duplicate action receipt'); actionReceipts.add(action.actionReceiptSha256)
    return { ...action, occurredMs: timestamp(action.occurredAt, 'action.occurredAt') }
  })
  if (!Array.isArray(manifest.grants) || !manifest.grants.length || manifest.grants.length > 1000) throw fail('INVALID_MANIFEST', 'grants invalid')
  const grantIds = new Set()
  const grants = manifest.grants.map((grant, index) => {
    for (const key of ['grantIdHash', 'scopeHash', 'sessionIdHash', 'principalBindingSha256', 'grantReceiptSha256', 'revocationReceiptSha256', 'observerHash']) hash(grant?.[key], `grants[${index}].${key}`)
    if (grantIds.has(grant.grantIdHash)) throw fail('INVALID_MANIFEST', 'duplicate grant'); grantIds.add(grant.grantIdHash)
    return { ...grant, grantedMs: timestamp(grant.grantedAt, 'grant.grantedAt'), revokedMs: timestamp(grant.revokedAt, 'grant.revokedAt') }
  })
  const closure = manifest.closure || {}
  for (const key of ['terminationReceiptSha256', 'sessionIdHash', 'principalBindingSha256', 'observerHash']) hash(closure[key], `closure.${key}`)
  integer(closure.residualGrantCount, 'closure.residualGrantCount', 0, 1000000); const observedMs = timestamp(closure.observedAt, 'closure.observedAt')
  return { manifest, evaluationMs, session, requestedMs, activatedMs, expiresMs, terminatedMs, policy, allowedActions, allowedResources, actions, grants, closure, observedMs }
}

export function inspectBreakGlassManifestJson(manifestJson) {
  const { manifest, session, policy, actions, grants } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), sessionIdHash: session.sessionIdHash, principalBindingSha256: session.principalBindingSha256, allowedActionCount: policy.allowedActionIdHashes.length, allowedResourceCount: policy.allowedResourceHashes.length, actionCount: actions.length, grantCount: grants.length, grantsAccess: false, queriesLiveIdentity: false }
}

export function evaluateBreakGlassManifest(manifestJson) {
  const { manifest, evaluationMs, session, requestedMs, activatedMs, expiresMs, terminatedMs, policy, allowedActions, allowedResources, actions, grants, closure, observedMs } = parseManifest(manifestJson)
  const sessionChronologyValid = requestedMs <= activatedMs && activatedMs < terminatedMs && terminatedMs <= expiresMs && expiresMs <= evaluationMs
  const sessionDurationSatisfied = terminatedMs - activatedMs <= policy.maxSessionMs && expiresMs - activatedMs <= policy.maxSessionMs
  const actionChronologyValid = actions.every((action, index) => action.occurredMs >= activatedMs && action.occurredMs <= terminatedMs && (index === 0 || action.occurredMs >= actions[index - 1].occurredMs))
  const actionsAllowlisted = actions.every(action => allowedActions.has(action.actionIdHash))
  const resourcesAllowlisted = actions.every(action => allowedResources.has(action.resourceHash))
  const bindingsSatisfied = actions.every(action => action.sessionIdHash === session.sessionIdHash && action.principalBindingSha256 === session.principalBindingSha256) && grants.every(grant => grant.sessionIdHash === session.sessionIdHash && grant.principalBindingSha256 === session.principalBindingSha256) && closure.sessionIdHash === session.sessionIdHash && closure.principalBindingSha256 === session.principalBindingSha256
  const grantChronologyValid = grants.every(grant => grant.grantedMs >= activatedMs && grant.grantedMs <= terminatedMs && grant.revokedMs >= grant.grantedMs && grant.revokedMs <= observedMs)
  const closureChronologyValid = observedMs >= terminatedMs && observedMs <= evaluationMs
  const declaredGrantsClosed = closure.residualGrantCount === 0 && grants.every(grant => grant.revocationReceiptSha256 !== '0'.repeat(64))
  const distinctObserverCount = new Set([...actions.map(row => row.observerHash), ...grants.map(row => row.observerHash), closure.observerHash]).size
  const observerThresholdSatisfied = distinctObserverCount >= policy.minDistinctObservers
  const evidenceFresh = evaluationMs - observedMs >= 0 && evaluationMs - observedMs <= policy.maxEvidenceAgeMs
  const checks = { sessionChronologyValid, sessionDurationSatisfied, actionChronologyValid, actionsAllowlisted, resourcesAllowlisted, bindingsSatisfied, grantChronologyValid, closureChronologyValid, declaredGrantsClosed, observerThresholdSatisfied, evidenceFresh }
  const verified = Object.values(checks).every(Boolean)
  return { schemaVersion: 1, verdict: verified ? 'break-glass-settled' : 'not-settled', proofIdHash: sha256(manifest.proofId), sessionIdHash: session.sessionIdHash, emergencyRequestSha256: session.emergencyRequestSha256, approvalReceiptSha256: session.approvalReceiptSha256, principalBindingSha256: session.principalBindingSha256, incidentSha256: session.incidentSha256, policySha256: session.policySha256, checks, disclosures: { actionCount: actions.length, grantCount: grants.length, distinctObserverCount, elapsedMs: terminatedMs - activatedMs, declaredResidualGrantCount: closure.residualGrantCount }, grantsAccess: false, grantsApproval: false, grantsWaiver: false, authenticatesReceipts: false, queriesLiveIdentity: false, provesAbsenceOfUndeclaredActions: false, provesAbsenceOfUndeclaredGrants: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat; const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const realRel = relative(await realpath(root), await realpath(absolute)); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(absolute, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyBreakGlassManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateBreakGlassManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `break-glass-settlement-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
