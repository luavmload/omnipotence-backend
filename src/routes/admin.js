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
        const db = getDB()
        const salt = crypto.randomBytes(16).toString('hex')
        const hash = crypto.scryptSync(password, salt, 64).toString('hex')
        try {
            await db.query(
                'INSERT INTO admins (username, salt, hash, display_name) VALUES ($1, $2, $3, $4)',
                [username, salt, hash, displayName || username]
            )
        } catch (e) {
            if (e.code === '23505') return reply.code(409).send({ ok: false, error: 'User exists' })
            return reply.code(500).send({ ok: false, error: 'Failed to save' })
        }
        await saveAdmins()
        return { ok: true, admin: { username, displayName: displayName || username } }
    })

    fastify.put(`${ADMIN_API_PREFIX}/admins/:username`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const target = request.params.username
        const { password, displayName, username: newUsername } = request.body || {}
        const a = findAdmin(target)
        if (!a) return reply.code(404).send({ ok: false, error: 'Not found' })
        const db = getDB()
        if (newUsername !== undefined && newUsername !== target) {
            if (!newUsername.trim()) return reply.code(400).send({ ok: false, error: 'Username cannot be empty' })
            if (findAdmin(newUsername)) return reply.code(409).send({ ok: false, error: 'Username taken' })
            await db.query('UPDATE admins SET username = $1 WHERE username = $2', [newUsername.trim(), target])
            if (request.adminUser === target) {
                for (const [token, session] of sessions) {
                    if (session.user === target) {
                        session.user = newUsername.trim()
                    }
                }
            }
        }
        if (displayName !== undefined) {
            await db.query('UPDATE admins SET display_name = $1 WHERE username = $2', [displayName, newUsername || target])
        }
        if (password) {
            const salt = crypto.randomBytes(16).toString('hex')
            const hash = crypto.scryptSync(password, salt, 64).toString('hex')
            await db.query('UPDATE admins SET salt = $1, hash = $2 WHERE username = $3', [salt, hash, newUsername || target])
        }
        await saveAdmins()
        return { ok: true }
    })

    fastify.delete(`${ADMIN_API_PREFIX}/admins/:username`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const target = request.params.username
        const admins = getAdmins()
        if (admins.length <= 1) return reply.code(400).send({ ok: false, error: 'Cannot delete last admin' })
        const db = getDB()
        await db.query('DELETE FROM admins WHERE username = $1', [target])
        await saveAdmins()
        return { ok: true }
    })

    // Detection config
    fastify.get(`${ADMIN_API_PREFIX}/detection`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const config = await getDetectionConfig()
        return { ok: true, ...config }
    })

    fastify.put(`${ADMIN_API_PREFIX}/detection`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { status, version } = request.body || {}
        const updates = {}
        if (status !== undefined) {
            if (!['detected', 'undetected'].includes(status)) return reply.code(400).send({ ok: false, error: 'Status must be detected or undetected' })
            updates.status = status
        }
        if (version !== undefined) updates.version = String(version)
        const merged = await updateDetectionConfig(updates)
        const ok = await saveDetectionConfig(merged)
        if (!ok) return reply.code(500).send({ ok: false, error: 'Failed to save' })
        return { ok: true, ...merged }
    })

    // Key CRUD
    fastify.get(`${ADMIN_API_PREFIX}/keys`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = getDB()
        const page = Math.max(1, parseInt(request.query.page) || 1)
        const perPage = Math.min(200, Math.max(10, parseInt(request.query.perPage) || 25))
        const search = request.query.search || ''
        const offset = (page - 1) * perPage
        const searchParam = search ? `%${search}%` : ''

        const totalResult = await db.query(
            "SELECT COUNT(*) as count FROM keys WHERE $1 = '' OR key ILIKE $1",
            [searchParam]
        )
        const total = parseInt(totalResult.rows[0].count)

        const rowsResult = await db.query(
            'SELECT key, used, banned, ban_reason, hwid, ip, uses_count, created_by, created_at, last_verified FROM keys WHERE $1 = \'\' OR key ILIKE $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
            [searchParam, perPage, offset]
        )

        return { ok: true, total, page, perPage, keys: rowsResult.rows }
    })

    fastify.get(`${ADMIN_API_PREFIX}/key/:key`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = getDB()
        const result = await db.query('SELECT * FROM keys WHERE key = $1', [request.params.key])
        if (result.rows.length === 0) return reply.code(404).send({ ok: false, error: 'Not found' })
        return { ok: true, key: result.rows[0] }
    })

    fastify.post(`${ADMIN_API_PREFIX}/generate`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { count = 1, prefix = 'OMNIPOTENCE' } = request.body || {}
        const db = getDB()
        const client = await db.connect()
        try {
            await client.query('BEGIN')
            for (let i = 0; i < Math.min(1000, count); i++) {
                const key = `${prefix}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
                await client.query('INSERT INTO keys (key, created_by) VALUES ($1, $2)', [key, request.adminUser || 'admin'])
            }
            await client.query('COMMIT')
        } catch (e) {
            await client.query('ROLLBACK')
            throw e
        } finally {
            client.release()
        }
        return { ok: true, created: Math.min(1000, count) }
    })

    fastify.post(`${ADMIN_API_PREFIX}/ban`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key, reason = '' } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = getDB()
        await db.query('UPDATE keys SET banned = 1, ban_reason = $1 WHERE key = $2', [reason, key])
        return { ok: true }
    })

    fastify.post(`${ADMIN_API_PREFIX}/unban`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = getDB()
        await db.query('UPDATE keys SET banned = 0, ban_reason = NULL WHERE key = $1', [key])
        return { ok: true }
    })

    fastify.post(`${ADMIN_API_PREFIX}/key/reset`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const { key } = request.body || {}
        if (!key) return reply.code(400).send({ ok: false, error: 'Missing key' })
        const db = getDB()
        await db.query('UPDATE keys SET used = 0, hwid = NULL, ip = NULL WHERE key = $1', [key])
        return { ok: true }
    })

    fastify.delete(`${ADMIN_API_PREFIX}/key/:key`, async (request, reply) => {
        if (!requireAdmin(request, reply) || !apiLimiter(request, reply)) return
        const db = getDB()
        await db.query('DELETE FROM keys WHERE key = $1', [request.params.key])
        return { ok: true }
    })
}
