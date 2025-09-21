import crypto from 'crypto'

const store = new Map()

function genId() {
  return crypto.randomBytes(12).toString('hex')
}

export function createChallenge(data) {
  const id = genId()
  const now = Date.now()
  const expiresAt = now + (data.ttlMs || 5 * 60 * 1000)
  const record = { id, createdAt: now, expiresAt, ...data }
  store.set(id, record)
  return record
}

export function getChallenge(id) {
  const record = store.get(id)
  if (!record) return null
  if (Date.now() > record.expiresAt) {
    store.delete(id)
    return null
  }
  return record
}

export function deleteChallenge(id) {
  store.delete(id)
}

export function cleanupExpired() {
  const now = Date.now()
  for (const [id, rec] of store) {
    if (now > rec.expiresAt) store.delete(id)
  }
}


