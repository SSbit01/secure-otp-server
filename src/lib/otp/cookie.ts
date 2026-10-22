import { deleteCookie, setCookie } from "hono/cookie";
import { OTP_COOKIE_PREFIX } from "@/custom/config";
import isProduction from "@/lib/production";
import type { Context } from "hono";

const COOKIE_OTP = "o";

let cookieOtp = "";

export function deleteOtpCookie(c: Context) {
  deleteCookie(c, getOtpCookieName(c));
}

export function getOtpCookieName(c: Context): string {
  if (!cookieOtp) {
    cookieOtp = isProduction(c) ? (OTP_COOKIE_PREFIX + COOKIE_OTP) : COOKIE_OTP;
  }

  return cookieOtp;
}

export function setOtpCookie(c: Context, otpData: string, expires: Date) {
  setCookie(
    c,
    getOtpCookieName(c),
    otpData,
    {
      expires,
      httpOnly: true,
      path: "/",
      secure: isProduction(c),
      sameSite: "strict",
      partitioned: false
    }
  );
}
