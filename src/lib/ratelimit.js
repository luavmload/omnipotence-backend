export function createRateLimiter({ windowMs = 60000, max = 30 } = {}) {
    const hits = new Map()

    const cleanup = setInterval(() => {
        const now = Date.now()
        for (const [key, record] of hits) {
            if (now - record.reset > windowMs) {
                hits.delete(key)
            }
        }
    }, windowMs * 2)
    cleanup.unref()

    return function rateLimit(request, reply) {
        const ip = request.ip
        const now = Date.now()
        let record = hits.get(ip)

        if (!record || now > record.reset) {
            record = { count: 0, reset: now + windowMs }
            hits.set(ip, record)
        }

        record.count++

        const remaining = Math.max(0, max - record.count)
        reply.header('X-RateLimit-Limit', max)
        reply.header('X-RateLimit-Remaining', remaining)
        reply.header('X-RateLimit-Reset', Math.ceil(record.reset / 1000))

        if (record.count > max) {
            reply.code(429).send({ ok: false, error: 'Too many requests. Please slow down.' })
            return false
        }
        return true
    }
}
