export interface TotpEntry {
  /** platform name, TOTP code can be accessed by bot command `/otp name` */
  name: string
  /** TOTP secret */
  secret: string | `steam://${string}`
  /** user_ids who can acquire otp codes */
  authorized_ids?: number[]
}

export interface OtpBotConfig {
  /** telegram bot token */
  bot_token: string
  /** user_id of admin who can authorize other users*/
  admin: number
  /** TOTP generators */
  totp: TotpEntry[]
  proxy?: {
    host: string
    port: number
  }
}
