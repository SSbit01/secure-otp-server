import {
  OTP_INVALID_BLOCK_SECONDS,
  OTP_MAX_AGE,
  OTP_RESEND_BLOCK_SECONDS,
} from "@/custom/otp"


export const OTP_INVALID_BLOCK_MS = OTP_INVALID_BLOCK_SECONDS * 1000

/**
 * It is used for `maxAge` in cookies due to the request delay.
 */
export const OTP_MAX_AGE_MINUS = OTP_MAX_AGE - 1

export const OTP_MAX_AGE_MS = OTP_MAX_AGE * 1000

export const OTP_RESEND_BLOCK_MS = OTP_RESEND_BLOCK_SECONDS * 1000