import {
  OTP_INVALID_BLOCK_SECONDS,
  OTP_MAX_AGE,
  OTP_RESEND_BLOCK_SECONDS,
} from "@/custom/otp"

import { KEK_ID_LENGTH } from "@/lib/crypto/id"
import { WRAPPED_DEK_BYTES } from "@/lib/crypto/symmetric/kek"
import { secondsToMs } from "@/lib/time"


export const METADATA_STRING_LENGTH = KEK_ID_LENGTH + Math.ceil(WRAPPED_DEK_BYTES / 3) * 4  // Because of Base64 padding.

export const OTP_INVALID_BLOCK_MS = secondsToMs(OTP_INVALID_BLOCK_SECONDS)
export const OTP_MAX_AGE_MS = secondsToMs(OTP_MAX_AGE)
export const OTP_RESEND_BLOCK_MS = secondsToMs(OTP_RESEND_BLOCK_SECONDS)