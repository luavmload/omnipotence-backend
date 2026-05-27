import Fastify from 'fastify'
import path from 'path'
import fastifyStatic from '@fastify/static'
import { ADMIN_BASE_PATH, VERIFY_SECRET } from './lib/config.js'
import { initDB } from './lib/db.js'
import { loadAdmins } from './lib/auth.js'
import { loadDetectionConfig, getDetectionConfig } from './lib/detection.js'
import registerAdminRoutes from './routes/admin.js'
import registerPublicRoutes from './routes/public.js'

const fastify = Fastify({
  logger: {
    transport: {
      target: 'pino-pretty',
      options: { translateTime: 'HH:MM:ss Z', ignore: 'pid,hostname' }
    }
  }
});

fastify.setNotFoundHandler(async (request, reply) => {
    const config = getDetectionConfig()
    return { status: config.status, version: config.version }
})

await initDB()
await loadAdmins()
await loadDetectionConfig()

await fastify.register(fastifyStatic, {
    root: path.join(process.cwd(), 'public', 'admin'),
    prefix: `${ADMIN_BASE_PATH}/`,
    index: 'index.html'
})

fastify.get(ADMIN_BASE_PATH, async (request, reply) => {
    return reply.redirect(`${ADMIN_BASE_PATH}/`)
})

await registerAdminRoutes(fastify)
await registerPublicRoutes(fastify)

try {
    await fastify.listen({ port: 1337, host: '0.0.0.0' })
} catch (err) {
    fastify.log.error(err)
    process.exit(1)
}
