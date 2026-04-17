import { decryptTextSymmetrically } from "@/lib/crypto/symmetric/dek";
import { ATTEMPTS, EXPIRES, OTP, OTP_BLOCK, RESEND_BLOCK } from "@/lib/otp/encode/token";
import { getReducedTimePrecision } from "@/lib/time";

/**
 * @import { OtpToken } from "@/lib/otp/encode/token"
 */

/**
 * @typedef {Object} OtpTokenData
 * @property {Date} expires
 * @property {boolean} [blocked]
 * @property {Date} [resendBlock]
 * @property {Date} [otpBlock]
 */

export const OTP_TOKEN_SEPARATOR = ",";

/**
 * @function blockOtpToken
 * @param {OtpToken} otpToken
 */
export function blockOtpToken(otpToken) {
  delete otpToken[OTP];
  delete otpToken[ATTEMPTS];
  delete otpToken[RESEND_BLOCK];
  delete otpToken[OTP_BLOCK];
}

/**
 * @function getOtpTokenData
 * @param {OtpToken} otpToken
 * @returns {OtpTokenData}
 */
export function getOtpTokenData(otpToken) {
  /**
   * @type {OtpTokenData}
   */
  const result = {
    expires: new Date(getReducedTimePrecision(otpToken[EXPIRES]))
  };

  if (!otpToken[OTP]) {
    result.blocked = true;
  } else {
    if (otpToken[RESEND_BLOCK]) {
      result.resendBlock = new Date(getReducedTimePrecision(otpToken[RESEND_BLOCK], Math.ceil));
    }
    if (otpToken[OTP_BLOCK]) {
      result.otpBlock = new Date(getReducedTimePrecision(otpToken[OTP_BLOCK], Math.ceil));
    }
  }

  return result;
}

/**
 * @function getOtpTokenList
 * @param {CryptoKey} key
 * @param {string} ciphertext
 * @param {BufferSource} additionalData
 * @returns {Promise<string[]|undefined>}
 */
export async function getOtpTokenList(key, ciphertext, additionalData) {
  try {
    return (
      await decryptTextSymmetrically(key, ciphertext, additionalData)
    ).split(OTP_TOKEN_SEPARATOR);
  } catch {
    // It simply returns `undefined`.
  }
}
