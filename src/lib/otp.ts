import { setCookie, deleteCookie } from "hono/cookie"
import { ulid } from "ulid"

import { encryptOtp, decryptOtp } from "./crypto/otp.js"

import { maxAttempts, resendBlockSeconds, otpMaxDurationSeconds, createOtp } from "./custom/otp.js"
import sendOtp from "./custom/send.js"

import isProduction from "./production.js"

import type { Context } from "hono"
import type { CookieOptions } from "hono/utils/cookie"


const separator = ":"

const otpMaxDurationMs = otpMaxDurationSeconds * 1000
const resendBlockMs = resendBlockSeconds * 1000


export const cookieOtpName = "t"
export const keyOtpName = "e"


export async function createOtpCookie(
  c: Context,
  credential: string | number,
  otp: string | number,
  expires: number,
  resendBlockDate: string | number = "",
  attempts = maxAttempts,
  otpBlockDate: string | number | false | null | undefined = false
) {

  /**
   * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
   */
  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  let value = `${credential}${separator}${expires}${separator}${resendBlockDate}${separator}${otp}${separator}${attempts}`

  if (otpBlockDate) {
    value += `${separator}${otpBlockDate}`
  }

  const cookieOptions: CookieOptions = {
    expires: new Date(expires),
    httpOnly: true,
    maxAge: otpMaxDurationMs,
    secure: isProduction(c),
    sameSite: "strict",
    partitioned: false
  }

  const keyId = ulid()

  setCookie(c, cookieOtpName, await encryptOtp(c, value), cookieOptions)
  setCookie(c, keyOtpName, keyId, cookieOptions)

}


export async function createOtpAndSend(
  c: Context,
  credential: string | number,
  resent?: boolean,
  dateNow = Date.now()
): Promise<{
  expires: number
  resendBlockDate?: number
}> {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  const expires = dateNow + otpMaxDurationMs

  if (resent) {
    await createOtpCookie(c, credential, otp, expires)
    return { expires }
  }

  const resendBlockDate = dateNow + resendBlockMs

  await createOtpCookie(c, credential, otp, expires, resendBlockDate)

  return { expires, resendBlockDate }

}


export async function getOtpTokenData(
  c: Context,
  token: string
) {
  
  if (token) {
    try {
      // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
      return (await decryptOtp(c, token)).split(separator) as [credential: string, expires: string, resendBlockDate: string, otp: string, attempts: string, otpBlockDate?: string]
    } catch {}
  }
  
  deleteCookie(c, cookieOtpName)

}