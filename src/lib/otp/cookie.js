import { deleteCookie, setCookie } from "hono/cookie";
import { OTP_COOKIE_PREFIX } from "@/custom/otp";
import isProduction from "@/lib/production";

/**
 * @import { Context } from "hono"
 */

const COOKIE_OTP = "o";

let cookieOtp = "";

/**
 * @function deleteOtpCookie
 * @param {Context} c
 */
export function deleteOtpCookie( c ) {
  deleteCookie( c, getOtpCookieName( c ) );
}

/**
 * @function getOtpCookieName
 * @param {Context} c
 * @returns {string}
 */
export function getOtpCookieName( c ) {
  if ( !cookieOtp ) {
    cookieOtp = isProduction( c ) ? ( OTP_COOKIE_PREFIX + COOKIE_OTP ) : COOKIE_OTP;
  }

  return cookieOtp;
}

/**
 * @function setOtpCookie
 * @param {Context} c
 * @param {string} otpData
 * @param {Date} expires
 */
export function setOtpCookie( c, otpData, expires ) {
  setCookie(
    c,
    getOtpCookieName( c ),
    otpData,
    {
      expires,
      httpOnly: true,
      path: "/",
      secure: isProduction( c ),
      sameSite: "strict",
      partitioned: false
    }
  );
}
