import pg from 'pg'
import crypto from 'crypto'
import dns from 'dns'
import { DATABASE_URL } from './config.js'

let pool

export function getDB() {
    return pool
}

async function createPool() {
    const url = new URL(DATABASE_URL)
    try {
        const addresses = await dns.resolve4(url.hostname)
        url.hostname = addresses[0]
    } catch {}
    return new pg.Pool({
        connectionString: url.toString(),
        ssl: DATABASE_URL.includes('supabase.co') || DATABASE_URL.includes('render.com')
            ? { rejectUnauthorized: false }
            : false,
    })
}

export async function initDB() {
    if (!DATABASE_URL) {
        throw new Error('DATABASE_URL environment variable is required')
    }

    pool = await createPool()

    await pool.query(`
        CREATE TABLE IF NOT EXISTS keys (
            id SERIAL PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            used INTEGER DEFAULT 0,
            banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            hwid TEXT,
            ip TEXT,
            uses_count INTEGER DEFAULT 0,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_verified TIMESTAMP
        )
    `)

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            hash TEXT NOT NULL,
            display_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)

    await pool.query(`
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value JSONB NOT NULL
        )
    `)

    const adminCount = await pool.query('SELECT COUNT(*) as count FROM admins')
    if (parseInt(adminCount.rows[0].count) === 0) {
        const defaultUser = process.env.ADMIN_USER || 'admin'
        const defaultPass = process.env.ADMIN_PASSWORD || 'changeme123'
        const salt = crypto.randomBytes(16).toString('hex')
        const hash = crypto.scryptSync(defaultPass, salt, 64).toString('hex')
        await pool.query(
            'INSERT INTO admins (username, salt, hash, display_name) VALUES ($1, $2, $3, $4)',
            [defaultUser, salt, hash, 'Administrator']
        )
    }

    const configCount = await pool.query("SELECT COUNT(*) as count FROM config WHERE key = 'detection'")
    if (parseInt(configCount.rows[0].count) === 0) {
        await pool.query(
            "INSERT INTO config (key, value) VALUES ('detection', $1)",
            [JSON.stringify({ status: 'undetected', version: '1.0' })]
        )
    }

    const keyCount = await pool.query('SELECT COUNT(*) as count FROM keys')
    if (parseInt(keyCount.rows[0].count) === 0) {
        const inserts = []
        for (let i = 0; i < 5; i++) {
            const key = `OMNIPOTENCE-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
            inserts.push(pool.query('INSERT INTO keys (key) VALUES ($1)', [key]))
        }
        await Promise.all(inserts)
    }
}
