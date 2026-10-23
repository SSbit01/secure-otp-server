/**
 * IMPORTANT!
 *
 * ORDER IS SET MANUALLY IN `createEncodedOtpToken` AND `decodeOtpToken` FOR BETTER PERFORMANCE
 * (no need to create additional objects and arrays).
 */

import { OTP_ATTEMPTS_BLOCK, OTP_LENGTH, OTP_MAX_ATTEMPTS, OTP_REGEX } from "@/custom/config";
import { compressNumber, decompressNumber } from "@/lib/codec";
import { OTP_INVALID_BLOCK_MS, OTP_MAX_AGE_MS, OTP_RESEND_BLOCK_MS } from "@/lib/calculations";

export type OtpToken = [
  credential: string,
  expires: number,
  otp?: string,
  attempts?: number,
  resendBlock?: number,
  otpBlock?: number
];

export const CREDENTIAL = 0;
export const EXPIRES = 1;
export const OTP = 2;
export const ATTEMPTS = 3;
export const RESEND_BLOCK = 4;
export const OTP_BLOCK = 5;

const OTP_SEPARATOR = "|";
const OTP_DOUBLE_SEPARATOR = OTP_SEPARATOR + OTP_SEPARATOR;

function encodeCredential(credential: string): string {
  return encodeURI(credential);
}

function decodeCredential(encodedCredential: string): string {
  return decodeURI(encodedCredential).trim();
}

export function createEncodedOtpToken(
  credential: NonNullable<OtpToken[typeof CREDENTIAL]>,
  expires: NonNullable<OtpToken[typeof EXPIRES]>,
  otp: NonNullable<OtpToken[typeof OTP]>,
  resendBlock: NonNullable<OtpToken[typeof RESEND_BLOCK]>
) {
  return (
    encodeCredential(credential) + OTP_SEPARATOR +
    compressNumber(expires) + OTP_SEPARATOR +
    otp + OTP_SEPARATOR +
    OTP_MAX_ATTEMPTS + OTP_SEPARATOR +
    compressNumber(resendBlock)
  );
}

/**
 * @function decodeOtpToken
 * @param {string} encodedOtpToken
 * @param {number} [dateNow]
 * @returns {OtpToken|undefined} If it doesn't return anything, it means the token is invalid, and maybe the keys were compromised.
 */
export function decodeOtpToken(encodedOtpToken: string, dateNow = Date.now()): OtpToken | undefined {
  const otpToken: any = encodedOtpToken.split(OTP_SEPARATOR);

  otpToken[EXPIRES] = decompressNumber(otpToken[EXPIRES]);

  if ((otpToken[EXPIRES] - dateNow) > OTP_MAX_AGE_MS) {
    return;
  }

  try {
    otpToken[CREDENTIAL] = decodeCredential(otpToken[CREDENTIAL]);
  } catch {
    return;
  }

  if (!otpToken[CREDENTIAL]) {
    return;
  }

  if (otpToken[OTP]) {
    if (otpToken[OTP].length !== OTP_LENGTH || !OTP_REGEX.test(otpToken[OTP])) {
      return;
    }
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS];
    /**
     * `otpToken[ATTEMPTS]` can't be zero because it's automatically deleted.
     */
    if (isNaN(otpToken[ATTEMPTS]) || otpToken[ATTEMPTS] <= 0 || otpToken[ATTEMPTS] > OTP_MAX_ATTEMPTS) {
      return;
    }
    if (otpToken[RESEND_BLOCK]) {
      otpToken[RESEND_BLOCK] = decompressNumber(otpToken[RESEND_BLOCK]);
      if ((otpToken[RESEND_BLOCK] - dateNow) > OTP_RESEND_BLOCK_MS) {
        return;
      }
    }
    if (otpToken[OTP_BLOCK]) {
      if (otpToken[ATTEMPTS] > OTP_ATTEMPTS_BLOCK) {
        return;
      }
      otpToken[OTP_BLOCK] = decompressNumber(otpToken[OTP_BLOCK]);
      if ((otpToken[OTP_BLOCK] - dateNow) > OTP_INVALID_BLOCK_MS) {
        return;
      }
    }
  } else if (otpToken[ATTEMPTS] || otpToken[RESEND_BLOCK] || otpToken[OTP_BLOCK]) {
    return;
  }

  return otpToken;
}

export function encodeOtpToken(otpToken: OtpToken): string {
  let result = encodeCredential(otpToken[CREDENTIAL]) + OTP_SEPARATOR +
    compressNumber(otpToken[EXPIRES]);

  if (otpToken[OTP]) {
    result += OTP_SEPARATOR +
      otpToken[OTP] + OTP_SEPARATOR +
      otpToken[ATTEMPTS];
    if (otpToken[RESEND_BLOCK]) {
      result += OTP_SEPARATOR +
        compressNumber(otpToken[RESEND_BLOCK]);
      if (otpToken[OTP_BLOCK]) {
        result += OTP_SEPARATOR +
          compressNumber(otpToken[OTP_BLOCK]);
      }
    } else if (otpToken[OTP_BLOCK]) {
      result += OTP_DOUBLE_SEPARATOR +
        compressNumber(otpToken[OTP_BLOCK]);
    }
  }

  return result;
}
