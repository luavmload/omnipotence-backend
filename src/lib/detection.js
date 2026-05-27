import fs from 'fs/promises'
import path from 'path'
import { DETECTION_FILE } from './config.js'

const OLD_DETECTION_FILE = path.join(path.dirname(DETECTION_FILE), 'detection.json')

let detectionConfig = { status: 'undetected', version: '1.0' }

export async function loadDetectionConfig() {
    try {
        const raw = await fs.readFile(DETECTION_FILE, 'utf8')
        detectionConfig = { ...detectionConfig, ...JSON.parse(raw) }
    } catch (e) {
        // migrate from old filename
        try {
            const raw = await fs.readFile(OLD_DETECTION_FILE, 'utf8')
            detectionConfig = { ...detectionConfig, ...JSON.parse(raw) }
            await saveDetectionConfig()
            try { await fs.unlink(OLD_DETECTION_FILE) } catch (e) {}
        } catch (e2) {
            await saveDetectionConfig()
        }
    }
}

export async function saveDetectionConfig() {
    try {
        await fs.writeFile(DETECTION_FILE, JSON.stringify(detectionConfig, null, 2))
        return true
    } catch (e) {
        return false
    }
}

export function getDetectionConfig() {
    return detectionConfig
}

export function updateDetectionConfig(updates) {
    detectionConfig = { ...detectionConfig, ...updates }
}
