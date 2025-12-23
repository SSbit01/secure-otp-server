import { deleteCookie } from "hono/cookie"

import { OTP_COOKIE_PREFIX } from "@/custom/otp"
import isProduction from "@/lib/production"


/**
 * @import { Context } from "hono"
 */


const COOKIE_OTP = "o"


let cookieOtp = ""


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export function deleteOtpCookies(c) {
  deleteCookie(c, getOtpCookieName(c))
}


/**
 * @function getOtpCookieName
 * @param {Context} c
 * @returns {string}
 */
export function getOtpCookieName(c) {

  if (!cookieOtp) {
    cookieOtp = isProduction(c)
      ? (OTP_COOKIE_PREFIX + COOKIE_OTP)
      : COOKIE_OTP
  }

  return cookieOtp
  
}