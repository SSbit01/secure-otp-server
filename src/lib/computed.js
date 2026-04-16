import { OTP_INVALID_BLOCK_SECONDS, OTP_MAX_AGE, OTP_RESEND_BLOCK_SECONDS } from "@/custom/otp";
import { bytesToBase64Length } from "@/lib/base64";
import { WRAPPED_DEK_BYTES } from "@/lib/crypto/symmetric/kek";
import { KEK_ID_BYTES } from "@/lib/kms";
import { secondsToMs } from "@/lib/time";

/**
 * Base64 encoded length.
 *
 * @type {number}
 */
export const KEK_ID_LENGTH = bytesToBase64Length( KEK_ID_BYTES );
export const ENVELOPE_ENCRYPTION_WRAP_LENGTH = KEK_ID_LENGTH + bytesToBase64Length( WRAPPED_DEK_BYTES );
export const OTP_INVALID_BLOCK_MS = secondsToMs( OTP_INVALID_BLOCK_SECONDS );
export const OTP_MAX_AGE_MS = secondsToMs( OTP_MAX_AGE );
export const OTP_RESEND_BLOCK_MS = secondsToMs( OTP_RESEND_BLOCK_SECONDS );
