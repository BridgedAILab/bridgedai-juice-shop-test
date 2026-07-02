import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, appendFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const SCHEMA_VERSION = '2026-05-01'

function env (name, fallback = '') {
  const value = process.env[name]
  return value === undefined || value === null || value === '' ? fallback : value
}

function readJsonFile (file) {
  const path = resolve(file)
  if (!existsSync(path)) return undefined
  return JSON.parse(readFileSync(path, 'utf8'))
}

function stableSuffix (value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 24)
}

function subject (extra = {}) {
  return {
    repository: env('GITHUB_REPOSITORY'),
    commitSha: env('GITHUB_SHA'),
    workflowRunId: env('GITHUB_RUN_ID'),
    runAttempt: env('GITHUB_RUN_ATTEMPT', '1'),
    jobName: env('GITHUB_JOB'),
    artifactDigest: env('BRIDGEDAI_ARTIFACT_DIGEST'),
    environment: env('BRIDGEDAI_ENVIRONMENT'),
    ...extra
  }
}

function envelope (signalType, options = {}) {
  const repo = env('GITHUB_REPOSITORY', 'unknown/repo')
  const runId = env('GITHUB_RUN_ID', 'unknown-run')
  const attempt = env('GITHUB_RUN_ATTEMPT', '1')
  const job = env('GITHUB_JOB', 'bridgedai')
  const suffix = options.suffix ? `:${options.suffix}` : ''
  const idempotencyKey = `github:${repo}:${runId}:${attempt}:${job}:${signalType}${suffix}`

  return {
    organizationId: env('BRIDGEDAI_ORG_ID'),
    provider: 'github',
    sourceSystem: 'github-actions',
    signalType,
    schemaVersion: SCHEMA_VERSION,
    externalId: idempotencyKey,
    idempotencyKey,
    observedAt: new Date().toISOString(),
    confidence: options.confidence ?? 'high',
    verificationLevel: options.verificationLevel ?? 'provider_authoritative',
    subject: options.subject ?? subject(),
    rawPayload: options.rawPayload ?? {},
    normalizedPayload: {
      repositoryFullName: repo,
      workflowRunId: runId,
      runAttempt: attempt,
      commitSha: env('GITHUB_SHA'),
      branch: env('GITHUB_REF_NAME'),
      projectId: env('BRIDGEDAI_PROJECT_ID'),
      artifactDigest: env('BRIDGEDAI_ARTIFACT_DIGEST'),
      artifactName: env('BRIDGEDAI_ARTIFACT_NAME', repo.split('/').pop()),
      ...options.normalizedPayload
    },
    evidenceHints: options.evidenceHints ?? [],
    graphHints: options.graphHints ?? [],
    metadata: { dataSource: 'production', emitDemo: false, ...(options.metadata ?? {}) }
  }
}

function summarizeNeeds () {
  try {
    const raw = env('BRIDGEDAI_NEEDS_JSON', '{}')
    const parsed = JSON.parse(raw)
    const entries = Object.entries(parsed).map(([name, value]) => ({
      name,
      result: value && typeof value === 'object' ? String(value.result ?? 'unknown') : 'unknown'
    }))
    const failed = entries.filter((job) => ['failure', 'cancelled', 'timed_out'].includes(job.result))
    return {
      entries,
      failed,
      status: failed.length > 0 ? 'failed' : 'completed'
    }
  } catch {
    return { entries: [], failed: [], status: 'completed' }
  }
}

function extractTrivyFindings (doc) {
  if (!doc || !Array.isArray(doc.Results)) return []
  const findings = []
  for (const result of doc.Results) {
    const target = result.Target
    const type = result.Type
    for (const vuln of result.Vulnerabilities ?? []) {
      findings.push({
        target,
        type,
        vulnerabilityId: vuln.VulnerabilityID,
        packageName: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion,
        severity: String(vuln.Severity ?? 'UNKNOWN').toLowerCase(),
        title: vuln.Title,
        primaryUrl: vuln.PrimaryURL,
        cvssSeverity: String(vuln.Severity ?? 'UNKNOWN').toLowerCase(),
        fixAvailable: Boolean(vuln.FixedVersion),
        references: Array.isArray(vuln.References) ? vuln.References.slice(0, 10) : []
      })
    }
  }
  return findings
}

function severityCounts (findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const finding of findings) {
    const severity = finding.severity in counts ? finding.severity : 'unknown'
    counts[severity] += 1
  }
  return counts
}

function appendSignals (signals) {
  const signalFile = resolve(env('BRIDGEDAI_SIGNAL_FILE', '.bridgedai/signals.jsonl'))
  mkdirSync(dirname(signalFile), { recursive: true })
  for (const signal of signals) {
    appendFileSync(signalFile, `${JSON.stringify(signal)}\n`, { encoding: 'utf8', mode: 0o644 })
  }
  console.log(`Wrote ${signals.length} BridgedAI signal(s) to ${signalFile}`)
}

const needs = summarizeNeeds()
const trivy = readJsonFile(env('BRIDGEDAI_TRIVY_JSON', '.bridgedai/trivy-results.json'))
const findings = extractTrivyFindings(trivy)
const counts = severityCounts(findings)
const highestSeverity =
  counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : counts.medium > 0 ? 'medium' : counts.low > 0 ? 'low' : 'none'

const signals = [
  envelope(needs.status === 'failed' ? 'build.failed' : 'build.completed', {
    rawPayload: { needs: needs.entries, failedJobs: needs.failed },
    normalizedPayload: {
      status: needs.status,
      failedJobCount: needs.failed.length,
      jobResults: needs.entries,
      workflowName: env('GITHUB_WORKFLOW')
    }
  }),
  envelope('container_image.scanned', {
    verificationLevel: 'scanner_observed',
    rawPayload: { scanner: 'trivy', counts, resultCount: findings.length },
    normalizedPayload: {
      scanner: 'trivy',
      artifactType: env('BRIDGEDAI_ARTIFACT_TYPE', 'source_archive'),
      severity: highestSeverity,
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      unknownCount: counts.unknown,
      scanSeverity: highestSeverity,
      fixAvailable: findings.some((finding) => finding.fixAvailable)
    }
  })
]

for (const finding of findings) {
  const key = `${finding.vulnerabilityId}:${finding.packageName}:${finding.installedVersion}:${finding.target}`
  signals.push(envelope('vulnerability.detected', {
    suffix: stableSuffix(key),
    verificationLevel: 'scanner_observed',
    subject: subject({ artifactDigest: env('BRIDGEDAI_ARTIFACT_DIGEST') }),
    rawPayload: finding,
    normalizedPayload: {
      scanner: 'trivy',
      severity: finding.severity,
      cvssSeverity: finding.cvssSeverity,
      vulnerabilityId: finding.vulnerabilityId,
      packageName: finding.packageName,
      installedVersion: finding.installedVersion,
      fixedVersion: finding.fixedVersion,
      fixAvailable: finding.fixAvailable,
      target: finding.target,
      title: finding.title,
      primaryUrl: finding.primaryUrl
    },
    metadata: { scanner: 'trivy', severity: finding.severity }
  }))
}

appendSignals(signals)
