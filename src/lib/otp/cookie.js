import { deleteCookie } from "hono/cookie"


/**
 * @import { Context } from "hono"
 */


export const COOKIE_OTP_ENCRYPTED_TOKENS = "t"
export const COOKIE_OTP_KEY_ID = "k"


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export default function deleteOtpCookies(c) {
  deleteCookie(c, COOKIE_OTP_ENCRYPTED_TOKENS)
  deleteCookie(c, COOKIE_OTP_KEY_ID)
}