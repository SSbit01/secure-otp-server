import { setCookie, deleteCookie } from "hono/cookie"

import createRandomID from "@/lib/crypto/id"
import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import getReducedTimePrecision from "@/lib/time"

import { deleteEncryptionKey } from "@/custom/kms"
import { maxAttempts, resendBlockSeconds, otpMaxDurationSeconds, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

import type { Context } from "hono"
import type { CookieOptions } from "hono/utils/cookie"


const separator = ":"

const otpMaxDurationMs = otpMaxDurationSeconds * 1000
const resendBlockMs = resendBlockSeconds * 1000


export const cookiekeyIDName = "e"
export const cookieOtpName = "t"


export async function createOtpCookie(
  c: Context,
  otp: string | number,
  credential: string | number,
  expires: number,
  resendBlockDate: string | number = "",
  attempts: string | number = maxAttempts,
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

  const keyID = createRandomID()

  setCookie(c, cookieOtpName, await encryptOtp(c, keyID, value, expires), cookieOptions)
  setCookie(c, cookiekeyIDName, keyID, cookieOptions)

}


export async function createOtpAndSend(
  c: Context,
  credential: string | number,
  resent?: boolean,
  dateNow = getReducedTimePrecision()
): Promise<{
  expires: number
  resendBlockDate?: number
}> {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  const expires = dateNow + otpMaxDurationMs

  if (resent) {
    await createOtpCookie(c, otp, credential, expires)
    return { expires }
  }

  const resendBlockDate = dateNow + resendBlockMs

  await createOtpCookie(c, otp, credential, expires, resendBlockDate)

  return { expires, resendBlockDate }

}


export async function deleteOtpData(c: Context, keyID: string) {
  deleteCookie(c, cookieOtpName)
  deleteCookie(c, cookiekeyIDName)
  await deleteEncryptionKey(c, keyID)
}


export async function getOtpTokenData(
  c: Context,
  keyID: string,
  token: string
) {
  
  if (keyID && token) {
    try {
      // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
      return (await decryptOtp(c, keyID, token))?.split(separator) as [credential: string, expires: string, resendBlockDate: string, otp: string, attempts: string, otpBlockDate?: string]
    } catch {}
  }

  await deleteOtpData(c, keyID)

}