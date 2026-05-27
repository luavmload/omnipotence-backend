import pg from 'pg'
import crypto from 'crypto'
import { DATABASE_URL } from './config.js'

const pool = new pg.Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL && (DATABASE_URL.includes('supabase.co') || DATABASE_URL.includes('render.com'))
        ? { rejectUnauthorized: false }
        : false,
})

export function getDB() {
    return pool
}

export async function initDB() {
    if (!DATABASE_URL) {
        throw new Error('DATABASE_URL environment variable is required')
    }

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

    // Seed default admin if admins table is empty
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

    // Seed default detection config if not set
    const configCount = await pool.query("SELECT COUNT(*) as count FROM config WHERE key = 'detection'")
    if (parseInt(configCount.rows[0].count) === 0) {
        await pool.query(
            "INSERT INTO config (key, value) VALUES ('detection', $1)",
            [JSON.stringify({ status: 'undetected', version: '1.0' })]
        )
    }

    // Seed sample keys if keys table is empty
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
