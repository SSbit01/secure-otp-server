import { decryptTextSymmetrically } from "@/lib/crypto";
import { ATTEMPTS, EXPIRES, OTP, OTP_BLOCK, RESEND_BLOCK } from "@/lib/otp/encode/token";
import { getReducedTimePrecision } from "@/lib/time";
import type { OtpToken } from "@/lib/otp/encode/token";

export interface OtpTokenData {
  expires: Date;
  blocked?: boolean;
  resendBlock?: Date;
  otpBlock?: Date;
}

export const OTP_TOKEN_SEPARATOR = ",";

export function blockOtpToken(otpToken: OtpToken) {
  /**
   * Do not use `delete` because it can break engine optimizations.
   */
  otpToken[OTP] = undefined;
  otpToken[ATTEMPTS] = undefined;
  otpToken[RESEND_BLOCK] = undefined;
  otpToken[OTP_BLOCK] = undefined;
}

export function getOtpTokenData(otpToken: OtpToken) {
  /**
   * @type {OtpTokenData}
   */
  const result: OtpTokenData = {
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

export async function getOtpTokenList(
  key: CryptoKey,
  ciphertext: string,
  additionalData: BufferSource
): Promise<string[] | undefined> {
  try {
    return (
      await decryptTextSymmetrically(key, ciphertext, additionalData)
    ).split(OTP_TOKEN_SEPARATOR);
  } catch {
    // It simply returns `undefined`.
  }
}
