import crypto from 'crypto'
import { ADMIN_API_PREFIX } from '../lib/config.js'
import { getDB } from '../lib/db.js'
import { requireAdmin, findAdmin, getAdmins, saveAdmins, createSession, verifyAdminCredentials, sessions, generateAntiTamperToken, consumeAntiTamperToken, extractFingerprint } from '../lib/auth.js'
import { getDetectionConfig, updateDetectionConfig, saveDetectionConfig } from '../lib/detection.js'
import { createRateLimiter } from '../lib/ratelimit.js'

const loginLimiter = createRateLimiter({ windowMs: 60000, max: 5 })
const apiLimiter = createRateLimiter({ windowMs: 60000, max: 120 })

export default async function registerAdminRoutes(fastify) {

    // Challenge endpoint (unauthenticated - issues per-page anti-tamper token + session nonce)
    fastify.get(`${ADMIN_API_PREFIX}/challenge`, async (request, reply) => {
        const token = generateAntiTamperToken()
        let nonce = null
        const authHeader = request.headers['authorization']
        const existingToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
        if (existingToken) {
            const session = sessions.get(existingToken)
            if (session) {
                nonce = crypto.randomBytes(16).toString('hex')
                session.boundNonce = nonce
            }
        }
        return { ok: true, antiTamper: token, nonce }
    })

    // Challenge alternative for sections served via <meta> injection (body-free)
    fastify.get(`${ADMIN_API_PREFIX}/tamper`, async (request, reply) => {
        const antiTamper = generateAntiTamperToken()
        reply.header('x-anti-tamper', antiTamper)
        reply.header('x-session-nonce', '')
        const authHeader = request.headers['authorization']
        const existingToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
        if (existingToken) {
            const session = sessions.get(existingToken)
            if (session) {
                const nonce = crypto.randomBytes(16).toString('hex')
                session.boundNonce = nonce
                reply.header('x-session-nonce', nonce)
            }
        }
        return { ok: true }
    })

    // Login
    fastify.post(`${ADMIN_API_PREFIX}/login`, async (request, reply) => {
        if (!loginLimiter(request, reply)) return
        const { username, password } = request.body || {}
        if (!username || !password) {
            return reply.code(400).send({ ok: false, error: 'Username and password required' })
        }
        const antiTamper = request.headers['x-anti-tamper']
        if (!consumeAntiTamperToken(antiTamper)) {
            return reply.code(401).send({ ok: false, error: 'Invalid or expired session. Please refresh the page.' })
        }
        try {
            const ok = verifyAdminCredentials(username, password)
            if (!ok) return reply.code(401).send({ ok: false, error: 'Invalid credentials' })
            const fp = extractFingerprint(request)
            const nonce = crypto.randomBytes(16).toString('hex')
            const token = createSession(username, fp, nonce)
            const a = findAdmin(username)
            reply.header('x-session-token', token)
            reply.header('x-session-nonce', nonce)
            return { ok: true, token, nonce, user: { username: a.username, displayName: a.displayName || a.username } }
        } catch (e) {
            request.log.error('login error', e)
            return reply.code(500).send({ ok: false, error: 'Server error' })
        }
    })

    // Admin CRUD
    fastify.get(`${ADMIN_API_PREFIX}/admins`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const safe = getAdmins().map(a => ({ username: a.username, displayName: a.displayName || '', createdAt: a.createdAt || null }))
        return { ok: true, admins: safe }
    })

    fastify.post(`${ADMIN_API_PREFIX}/admins`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { username, password, displayName } = request.body || {}
        if (!username || !password) return reply.code(400).send({ ok: false, error: 'username and password required' })
        if (findAdmin(username)) return reply.code(409).send({ ok: false, error: 'User exists' })
        const salt = crypto.randomBytes(16).toString('hex')
        const hash = crypto.scryptSync(password, salt, 64).toString('hex')
        const obj = { username, salt, hash, displayName: displayName || username, createdAt: new Date().toISOString() }
        getAdmins().push(obj)
        const ok = await saveAdmins()
        if (!ok) return reply.code(500).send({ ok: false, error: 'Failed to save' })
        return { ok: true, admin: { username: obj.username, displayName: obj.displayName } }
    })

    fastify.put(`${ADMIN_API_PREFIX}/admins/:username`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const target = request.params.username
        const { password, displayName, username: newUsername } = request.body || {}
        const a = findAdmin(target)
        if (!a) return reply.code(404).send({ ok: false, error: 'Not found' })
        if (newUsername !== undefined && newUsername !== target) {
            if (!newUsername.trim()) return reply.code(400).send({ ok: false, error: 'Username cannot be empty' })
            if (findAdmin(newUsername)) return reply.code(409).send({ ok: false, error: 'Username taken' })
            a.username = newUsername.trim()
            if (request.adminUser === target) {
                for (const [token, session] of sessions) {
                    if (session.user === target) {
                        session.user = newUsername.trim()
                    }
                }
            }
        }
        if (displayName !== undefined) a.displayName = displayName
        if (password) {
            const salt = crypto.randomBytes(16).toString('hex')
            const hash = crypto.scryptSync(password, salt, 64).toString('hex')
            a.salt = salt
            a.hash = hash
        }
        const ok = await saveAdmins()
        if (!ok) return reply.code(500).send({ ok: false, error: 'Failed to save' })
        return { ok: true }
    })

    fastify.delete(`${ADMIN_API_PREFIX}/admins/:username`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const target = request.params.username
        const admins = getAdmins()
        const idx = admins.findIndex(a => a.username === target)
        if (idx === -1) return reply.code(404).send({ ok: false, error: 'Not found' })
        if (admins.length <= 1) return reply.code(400).send({ ok: false, error: 'Cannot delete last admin' })
        admins.splice(idx, 1)
        const ok = await saveAdmins()
        if (!ok) return reply.code(500).send({ ok: false, error: 'Failed to save' })
        return { ok: true }
    })

    // Detection config
    fastify.get(`${ADMIN_API_PREFIX}/detection`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        return { ok: true, ...getDetectionConfig() }
    })

    fastify.put(`${ADMIN_API_PREFIX}/detection`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { status, version } = request.body || {}
        if (status !== undefined) {
            if (!['detected', 'undetected'].includes(status)) return reply.code(400).send({ ok: false, error: 'Status must be detected or undetected' })
            updateDetectionConfig({ status })
        }
        if (version !== undefined) updateDetectionConfig({ version: String(version) })
        const ok = await saveDetectionConfig()
        if (!ok) return reply.code(500).send({ ok: false, error: 'Failed to save' })
        return { ok: true, ...getDetectionConfig() }
    })

    // Key CRUD
    fastify.get(`${ADMIN_API_PREFIX}/keys`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = await getDB()
        const page = Math.max(1, parseInt(request.query.page) || 1)
        const perPage = Math.min(200, Math.max(10, parseInt(request.query.perPage) || 25))
        const search = request.query.search || ''

        const where = search ? `WHERE key LIKE '%' || ? || '%'` : ''
        const totalRow = await db.get(`SELECT COUNT(*) as count FROM keys ${where}`, ...(search ? [search] : []))
        const rows = await db.all(`SELECT key, used, banned, ban_reason, hwid, ip, uses_count, created_by, created_at, last_verified FROM keys ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, ...(search ? [search, perPage, (page - 1) * perPage] : [perPage, (page - 1) * perPage]))

        return { ok: true, total: totalRow.count, page, perPage, keys: rows }
    })

    fastify.get(`${ADMIN_API_PREFIX}/key/:key`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = await getDB()
        const entry = await db.get('SELECT * FROM keys WHERE key = ?', request.params.key)
        if (!entry) return reply.code(404).send({ ok: false, error: 'Not found' })
        return { ok: true, key: entry }
    })

    fastify.post(`${ADMIN_API_PREFIX}/generate`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { count = 1, prefix = 'OMNIPOTENCE' } = request.body || {}
        const db = await getDB()
        const inserts = []
        await db.exec('BEGIN')
        try {
            for (let i = 0; i < Math.min(1000, count); i++) {
                const key = `${prefix}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
                inserts.push(db.run('INSERT INTO keys (key, created_by) VALUES (?, ?)', key, request.adminUser || 'admin'))
            }
            await Promise.all(inserts)
            await db.exec('COMMIT')
        } catch (e) {
            await db.exec('ROLLBACK')
            throw e
        }
        return { ok: true, created: inserts.length }
    })

    fastify.post(`${ADMIN_API_PREFIX}/ban`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key, reason = '' } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = await getDB()
        await db.run('UPDATE keys SET banned = 1, ban_reason = ? WHERE key = ?', reason, key)
        return { ok: true }
    })

    fastify.post(`${ADMIN_API_PREFIX}/unban`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = await getDB()
        await db.run('UPDATE keys SET banned = 0, ban_reason = NULL WHERE key = ?', key)
        return { ok: true }
    })

    fastify.post(`${ADMIN_API_PREFIX}/key/reset`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = await getDB()
        await db.run('UPDATE keys SET used = 0, hwid = NULL, ip = NULL WHERE key = ?', key)
        return { ok: true }
    })

    fastify.delete(`${ADMIN_API_PREFIX}/key/:key`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = await getDB()
        await db.run('DELETE FROM keys WHERE key = ?', request.params.key)
        return { ok: true }
    })
}
