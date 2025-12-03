import {
  OTP_INVALID_BLOCK_SECONDS,
  OTP_MAX_AGE,
  OTP_RESEND_BLOCK_SECONDS,
} from "@/custom/otp"

import { secondsToMs } from "@/lib/time"


export const OTP_INVALID_BLOCK_MS = secondsToMs(OTP_INVALID_BLOCK_SECONDS)

export const OTP_MAX_AGE_MS = secondsToMs(OTP_MAX_AGE)

export const OTP_RESEND_BLOCK_MS = secondsToMs(OTP_RESEND_BLOCK_SECONDS)