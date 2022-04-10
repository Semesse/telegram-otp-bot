import winston = require('winston')
import { format, inspect } from 'util'

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    {
      transform(info, opts) {
        const args = info[Symbol.for('splat') as unknown as any]
        if (args) {
          info.message = format(info.message, ...args.map(inspect))
        }
        return info
      },
    },
    winston.format.colorize({
      all: true,
    }),
    winston.format.timestamp({
      format: 'MM-DD HH:mm:ss',
    }),
    winston.format.printf((info) => `[${info.level}](${info.timestamp}):${info.message}`),
  ),
  transports: [
    // new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.Console(),
  ],
})
