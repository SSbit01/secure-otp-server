import { deleteCookie } from "hono/cookie"

import { OTP_COOKIE_PREFIX } from "@/custom/otp"
import isProduction from "@/lib/production"


/**
 * @import { Context } from "hono"
 */


export const COOKIE_OTP_ENCRYPTED_TOKENS = "t"
export const COOKIE_OTP_KEY_ID = "k"


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export function deleteOtpCookies(c) {
  deleteCookie(c, getCookieName(c, COOKIE_OTP_ENCRYPTED_TOKENS))
  deleteCookie(c, getCookieName(c, COOKIE_OTP_KEY_ID))
}


/**
 * @function getCookieName
 * @param {Context} c
 * @param {string} name
 * @returns {string}
 */
export function getCookieName(c, name) {

  if (isProduction(c)) {
    name = OTP_COOKIE_PREFIX + name
  }

  return name

}