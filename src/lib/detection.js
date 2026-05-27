import { getDB } from './db.js'

let cachedConfig = null

export async function loadDetectionConfig() {
    try {
        const db = getDB()
        const result = await db.query("SELECT value FROM config WHERE key = 'detection'")
        if (result.rows.length > 0) {
            cachedConfig = result.rows[0].value
            return cachedConfig
        }
    } catch (e) {}
    cachedConfig = { status: 'undetected', version: '1.0' }
    return cachedConfig
}

export async function saveDetectionConfig(config) {
    try {
        const db = getDB()
        await db.query(
            "INSERT INTO config (key, value) VALUES ('detection', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            [JSON.stringify(config)]
        )
        cachedConfig = config
        return true
    } catch (e) {
        return false
    }
}

export function getDetectionConfig() {
    return cachedConfig || { status: 'undetected', version: '1.0' }
}

export async function updateDetectionConfig(updates) {
    const current = getDetectionConfig()
    const merged = { ...current, ...updates }
    cachedConfig = merged
    return merged
}
