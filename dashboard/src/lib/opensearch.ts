import { config } from './config'

const OS_URL = config.opensearchUrl

export async function osQuery(method: string, path: string, body?: unknown) {
  const res = await fetch(`${OS_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`OpenSearch ${method} ${path}: ${res.status} ${text}`)
  }
  return res.json()
}

export function getIndexPattern() {
  return `logs-${config.clientId.toLowerCase()}-*`
}

export function getCurrentIndex() {
  const now = new Date()
  return `logs-${config.clientId.toLowerCase()}-${now.getFullYear()}.${String(now.getMonth() + 1).padStart(2, '0')}`
}
