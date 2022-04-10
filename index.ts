import { bot } from './bot'
import { logger } from './logger'

bot.launch()

logger.info('bot started')

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'))
process.once('SIGTERM', () => bot.stop('SIGTERM'))
