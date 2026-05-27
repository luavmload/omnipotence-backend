import crypto from 'crypto'
import { SESSION_TTL_MS, ANTI_TAMPER_TTL_MS } from './config.js'
import { getDB } from './db.js'

export const sessions = new Map()
export const antiTamperTokens = new Map()

let admins = []

// --- Admin loading / CRUD ---

export async function loadAdmins() {
    try {
        const db = getDB()
        const result = await db.query('SELECT username, salt, hash, display_name, created_at FROM admins ORDER BY created_at ASC')
        admins = result.rows.map(r => ({
            username: r.username,
            salt: r.salt,
            hash: r.hash,
            displayName: r.display_name,
            createdAt: r.created_at,
        }))
    } catch (e) {
        admins = []
    }
}

export function getAdmins() {
    return admins
}

export function findAdmin(username) {
    return admins.find(a => a.username === username)
}

export function verifyAdminCredentials(username, password) {
    const a = findAdmin(username)
    if (!a) return false
    const derived = crypto.scryptSync(password, a.salt, 64).toString('hex')
    return derived === a.hash
}

export async function saveAdmins() {
    try {
        const db = getDB()
        // Re-sync from DB
        const result = await db.query('SELECT username, salt, hash, display_name, created_at FROM admins ORDER BY created_at ASC')
        admins = result.rows.map(r => ({
            username: r.username,
            salt: r.salt,
            hash: r.hash,
            displayName: r.display_name,
            createdAt: r.created_at,
        }))
        return true
    } catch (e) {
        return false
    }
}

// --- Anti-tamper nonce system ---

export function generateAntiTamperToken() {
    const token = crypto.randomBytes(24).toString('hex')
    antiTamperTokens.set(token, { createdAt: Date.now() })
    return token
}

export function verifyAntiTamperToken(token) {
    if (!token) return false
    const entry = antiTamperTokens.get(token)
    if (!entry) return false
    if (Date.now() - entry.createdAt > ANTI_TAMPER_TTL_MS) {
        antiTamperTokens.delete(token)
        return false
    }
    return true
}

export function consumeAntiTamperToken(token) {
    if (!verifyAntiTamperToken(token)) return false
    antiTamperTokens.delete(token)
    return true
}

function cleanupAntiTamperTokens() {
    const now = Date.now()
    for (const [token, entry] of antiTamperTokens) {
        if (now - entry.createdAt > ANTI_TAMPER_TTL_MS) {
            antiTamperTokens.delete(token)
        }
    }
}
setInterval(cleanupAntiTamperTokens, ANTI_TAMPER_TTL_MS).unref()

// --- Client fingerprint ---

export function extractFingerprint(request) {
    const headers = request.headers
    return {
        ua: headers['user-agent'] || '',
        lang: headers['accept-language'] || '',
        encoding: headers['accept-encoding'] || '',
        plat: headers['sec-ch-ua-platform'] || '',
    }
}

export function fingerprintToString(fp) {
    if (!fp) return ''
    return `${fp.ua}|${fp.lang}|${fp.encoding}|${fp.plat}`
}

// --- Session management with rotation ---

export function createSession(user, fingerprint = null, boundNonce = null) {
    const token = crypto.randomBytes(36).toString('hex')
    sessions.set(token, { user, createdAt: Date.now(), fingerprint: fingerprintToString(fingerprint), boundNonce })
    return token
}

export function verifySession(token) {
    if (!token) return null
    const session = sessions.get(token)
    if (!session) return null
    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(token)
        return null
    }
    return session
}

export function rotateSession(oldToken) {
    const session = sessions.get(oldToken)
    if (!session) return null
    sessions.delete(oldToken)
    const newToken = crypto.randomBytes(36).toString('hex')
    session.createdAt = Date.now()
    sessions.set(newToken, session)
    return newToken
}

// --- Middleware ---

export function requireAdmin(request, reply) {
    const authHeader = request.headers['authorization']
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : request.headers['x-admin-token']
    const session = verifySession(token)
    if (!session) {
        reply.code(401).send({ ok: false, error: 'Unauthorized' })
        return false
    }

    const nonce = request.headers['x-session-nonce']
    if (session.boundNonce === undefined || session.boundNonce === null || session.boundNonce !== nonce) {
        sessions.delete(token)
        reply.code(401).send({ ok: false, error: 'Unauthorized' })
        return false
    }

    const fp = extractFingerprint(request)
    if (session.fingerprint && session.fingerprint !== fingerprintToString(fp)) {
        sessions.delete(token)
        reply.code(401).send({ ok: false, error: 'Unauthorized' })
        return false
    }

    const newToken = rotateSession(token)
    if (!newToken) {
        reply.code(401).send({ ok: false, error: 'Unauthorized' })
        return false
    }

    reply.header('x-session-token', newToken)
    request.adminUser = session.user
    return true
}
