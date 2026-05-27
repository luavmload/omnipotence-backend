import crypto from 'crypto'
import { getDB } from '../lib/db.js'
import { getDetectionConfig } from '../lib/detection.js'
import { createRateLimiter } from '../lib/ratelimit.js'
import { VERIFY_SECRET, VERIFY_TIMESTAMP_SKEW_MS } from '../lib/config.js'

const verifyLimiter = createRateLimiter({ windowMs: 60000, max: 10 })
const statusLimiter = createRateLimiter({ windowMs: 60000, max: 60 })

function computeProof(nonce, timestamp, valid) {
    const hmac = crypto.createHmac('sha256', VERIFY_SECRET)
    hmac.update(nonce)
    hmac.update(timestamp.toString())
    hmac.update(valid ? '1' : '0')
    return hmac.digest('hex')
}

export default async function registerPublicRoutes(fastify) {
    fastify.post('/verify', async (request, reply) => {
        if (!verifyLimiter(request, reply)) return
        const { key, hwid, nonce } = request.body || {}
        const ip = request.ip
        const timestamp = Date.now()

        if (!key || !hwid) return reply.code(400).send({ valid: false, error: 'Missing key or hwid' })

        // Anti-tamper nonce check
        if (nonce) {
            if (typeof nonce !== 'string' || nonce.length < 8) {
                return reply.code(400).send({ valid: false, error: 'Invalid request', timestamp, nonce, proof: computeProof(nonce, timestamp, false) })
            }
            const headerNonce = request.headers['x-verify-nonce']
            if (nonce !== headerNonce) {
                return reply.code(400).send({ valid: false, error: 'Invalid request', timestamp, nonce, proof: computeProof(nonce, timestamp, false) })
            }
        }

        const db = await getDB()
        const entry = await db.get('SELECT * FROM keys WHERE key = ?', key)
        if (!entry) {
            const res = { valid: false, error: 'Invalid key', timestamp }
            if (nonce) { res.nonce = nonce; res.proof = computeProof(nonce, timestamp, false) }
            return reply.code(404).send(res)
        }
        if (entry.banned) {
            const res = { valid: false, error: 'Key banned', reason: entry.ban_reason, timestamp }
            if (nonce) { res.nonce = nonce; res.proof = computeProof(nonce, timestamp, false) }
            return reply.code(403).send(res)
        }

        if (entry.used === 0) {
            await db.run('UPDATE keys SET used = 1, hwid = ?, ip = ?, last_verified = CURRENT_TIMESTAMP, uses_count = uses_count + 1 WHERE key = ?', hwid, ip, key)
            const res = { valid: true, message: 'Key activated', timestamp }
            if (nonce) { res.nonce = nonce; res.proof = computeProof(nonce, timestamp, true) }
            reply.header('x-proof', res.proof)
            return res
        }

        if (entry.hwid === hwid && entry.ip === ip) {
            await db.run('UPDATE keys SET last_verified = CURRENT_TIMESTAMP, uses_count = uses_count + 1 WHERE key = ?', key)
            const res = { valid: true, message: 'Key verified', timestamp }
            if (nonce) { res.nonce = nonce; res.proof = computeProof(nonce, timestamp, true) }
            reply.header('x-proof', res.proof)
            return res
        }

        const res = { valid: false, error: 'HWID or IP mismatch', timestamp }
        if (nonce) { res.nonce = nonce; res.proof = computeProof(nonce, timestamp, false) }
        return reply.code(403).send(res)
    })

    fastify.get('/status', async function handler(request, reply) {
        if (!statusLimiter(request, reply)) return
        const config = getDetectionConfig()
        return { status: config.status, version: config.version }
    })
}
