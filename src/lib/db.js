import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import crypto from 'crypto'
import { DB_FILE } from './config.js'

const dbPromise = open({
    filename: DB_FILE,
    driver: sqlite3.Database
})

export function getDB() {
    return dbPromise
}

export async function initDB() {
    const db = await dbPromise

    await db.exec(`
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
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

    try { await db.exec("ALTER TABLE keys ADD COLUMN banned INTEGER DEFAULT 0") } catch (e) {}
    try { await db.exec("ALTER TABLE keys ADD COLUMN ban_reason TEXT") } catch (e) {}
    try { await db.exec("ALTER TABLE keys ADD COLUMN uses_count INTEGER DEFAULT 0") } catch (e) {}
    try { await db.exec("ALTER TABLE keys ADD COLUMN created_by TEXT") } catch (e) {}

    await db.exec('CREATE INDEX IF NOT EXISTS idx_keys_used ON keys(used)')
    await db.exec('CREATE INDEX IF NOT EXISTS idx_keys_banned ON keys(banned)')
    await db.exec('CREATE INDEX IF NOT EXISTS idx_keys_last_verified ON keys(last_verified)')

    const row = await db.get('SELECT COUNT(*) as count FROM keys')
    if (row.count === 0) {
        const inserts = []
        for (let i = 0; i < 5; i++) {
            const key = `OMNIPOTENCE-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
            inserts.push(db.run('INSERT INTO keys (key) VALUES (?)', key))
        }
        await Promise.all(inserts)
    }
}
