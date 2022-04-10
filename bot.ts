import { HttpsProxyAgent } from 'https-proxy-agent'
import { Telegraf, Markup, Context } from 'telegraf'
import { logger } from './logger'
import { TotpService } from './otp'
import { OtpBotConfig } from './config'
import { v4 as uuid } from 'uuid'
import * as fs from 'fs'
import { Update } from 'telegraf/typings/core/types/typegram'

const otpService = new TotpService()
const config = JSON.parse(fs.readFileSync('otp.json').toString()) as OtpBotConfig
let agent: HttpsProxyAgent

if (config.proxy) agent = new HttpsProxyAgent(config.proxy)

export const bot = new Telegraf(config.bot_token, { telegram: { agent } })

enum Commands {
  otp = 'otp', // get totp code if authorized
  request = 'request', // request a one time code
}

const getUserName = (ctx: Context<Update>) =>
  ctx.from.username ? `@${ctx.from.username}` : `${ctx.from.first_name}(${ctx.from.id})`
const getCommandContent = (text: string, command: string) => text.slice(command.length + 2)
const requests: Map<string, () => void> = new Map()
const createCallbackPromise = (id: string) =>
  new Promise<void>((resolve) => {
    requests.set(id, resolve)
  })

bot.use((ctx, next) => {
  const { message_id, from, chat, date, ...other } = ctx.message || {}
  logger.info('%s: %s', ctx.from.username || ctx.from.first_name, other)
  next()
})

bot.start((ctx) => {
  logger.info('/start', ctx.from.id)
  ctx.reply(ctx.from.id.toString())
})

bot.help((ctx) => {
  ctx.reply(
    `Usage \\-
\`/otp {platform}\`
generates otp code for platform
\`/request {platform}\`
send a request to get otp code once`,
    { parse_mode: 'MarkdownV2' },
  )
})

bot.command(Commands.otp, async (ctx) => {
  const user = getUserName(ctx)
  const name = getCommandContent(ctx.message.text, Commands.otp)
  const totpEntry = config.totp.find((t) => t.name === name)
  if (!totpEntry) return ctx.reply(`no platform with name ${name}`)
  if (!totpEntry.authorized_ids.includes(ctx.from.id)) return ctx.reply(`not authorized`)
  const code = await otpService.getCode(totpEntry.secret)
  bot.telegram.sendMessage(config.admin, `${user} has generated TOTP code for ${name}`)
  return bot.telegram.sendMessage(ctx.chat.id, `\`${code}\``, {
    parse_mode: 'MarkdownV2',
    reply_to_message_id: ctx.message.message_id,
  })
})

bot.command(Commands.request, async (ctx) => {
  const user = getUserName(ctx)
  const name = getCommandContent(ctx.message.text, Commands.request)
  const totpEntry = config.totp.find((t) => t.name === name)
  if (!totpEntry) return ctx.reply(`no platform with name ${name}`)

  const requestId = uuid()
  const adminButtons = Markup.inlineKeyboard([[{ text: 'Approve', callback_data: requestId }]])
  ctx.reply('A request has been sent to admin, once approved, you can generate TOTP code for one time')
  const approvalMessage = await bot.telegram.sendMessage(config.admin, `${user} is requesting otp ${name}`, {
    reply_markup: adminButtons.reply_markup,
  })
  await createCallbackPromise(requestId)
  bot.telegram.editMessageReplyMarkup(approvalMessage.chat.id, approvalMessage.message_id, ctx.inlineMessageId, null)

  const generateId = uuid()
  const buttons = Markup.inlineKeyboard([[{ text: 'Generate TOTP Code', callback_data: generateId }]])
  const generateMessage = await bot.telegram.sendMessage(ctx.chat.id, `TOTP request for **${name}** approved`, {
    reply_markup: buttons.reply_markup,
    parse_mode: 'MarkdownV2',
  })
  await createCallbackPromise(generateId)
  bot.telegram.editMessageReplyMarkup(generateMessage.chat.id, generateMessage.message_id, ctx.inlineMessageId, null)

  const code = await otpService.getCode(totpEntry.secret)
  ctx.reply(`\`${code}\``, { parse_mode: 'MarkdownV2' })
  bot.telegram.sendMessage(config.admin, `${user} has generated TOTP code for ${name}`)
})

bot.action(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, async (ctx) => {
  const requestId = ctx.match[0]
  logger.info('handle callback for %s, %s', requestId, requests.has(requestId) ? 'found' : 'not found')
  if (requests.has(requestId)) {
    try {
      requests.get(requestId)()
    } catch (err) {
      logger.error('callback for %s faled, %s', requestId, err)
    }
    requests.delete(requestId)
  }
})
