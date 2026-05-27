import crypto from 'crypto'

export const ADMIN_BASE_PATH = process.env.ADMIN_BASE_PATH || '/dash'
export const ADMIN_API_PREFIX = `${ADMIN_BASE_PATH}/api`
export const ADMINS_FILE = process.env.ADMINS_FILE || './data/admins.json'
export const DETECTION_FILE = process.env.DETECTION_FILE || './data/status.json'
export const SESSION_TTL_MS = 1000 * 60 * 60 * 6
export const DB_FILE = process.env.DB_FILE || './data/keys.db'
export const ANTI_TAMPER_TTL_MS = 1000 * 60 * 5
export const VERIFY_SECRET = process.env.VERIFY_SECRET || 'AES256-GCM-SHA384'
export const VERIFY_TIMESTAMP_SKEW_MS = 1000 * 30
