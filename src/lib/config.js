import crypto from 'crypto'

export const ADMIN_BASE_PATH = process.env.ADMIN_BASE_PATH || '/dash'
export const ADMIN_API_PREFIX = `${ADMIN_BASE_PATH}/api`
export const SESSION_TTL_MS = 1000 * 60 * 60 * 6
export const ANTI_TAMPER_TTL_MS = 1000 * 60 * 5
export const DATABASE_URL = process.env.DATABASE_URL
export const VERIFY_SECRET = process.env.VERIFY_SECRET || 'changeme'
export const VERIFY_TIMESTAMP_SKEW_MS = 1000 * 30