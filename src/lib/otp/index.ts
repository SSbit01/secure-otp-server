import { getEnvOtpLength, getEnvOtpMaxAttempts, getEnvOtpRadix } from "#src/env";
import { decryptTextSymmetrically } from "#src/lib/crypto";
import { getReducedTimePrecision } from "#src/lib/time";
import { compressNumber, decompressNumber } from "#src/lib/codec";
import type { Context } from "hono";

type OtpToken = [
  credential: string,
  expires: number,
  otp?: string,
  attempts?: number,
  resendBlock?: number,
  otpBlock?: number
];

export interface OtpTokenData {
  expires: Date;
  blocked?: boolean;
  resendBlock?: Date;
  otpBlock?: Date;
}

export const CREDENTIAL = 0;
export const EXPIRES = 1;
export const OTP = 2;
export const ATTEMPTS = 3;
export const RESEND_BLOCK = 4;
export const OTP_BLOCK = 5;

export const OTP_TOKEN_SEPARATOR = ",";

export const regexOtp = /[a-z0-9]+/;

const OTP_SEPARATOR = "|";
const OTP_DOUBLE_SEPARATOR = OTP_SEPARATOR + OTP_SEPARATOR;

function decodeCredential(encodedCredential: string): string {
  return decodeURI(encodedCredential).trim();
}

function encodeCredential(credential: string): string {
  return encodeURI(credential);
}

export function blockOtpToken(otpToken: OtpToken) {
  /**
   * Do not use `delete` because it can break engine optimizations.
   */
  otpToken[OTP] = undefined;
  otpToken[ATTEMPTS] = undefined;
  otpToken[RESEND_BLOCK] = undefined;
  otpToken[OTP_BLOCK] = undefined;
}

export function createEncodedOtpToken(
  c: Context,
  credential: NonNullable<OtpToken[typeof CREDENTIAL]>,
  expires: NonNullable<OtpToken[typeof EXPIRES]>,
  otp: NonNullable<OtpToken[typeof OTP]>,
  resendBlock: NonNullable<OtpToken[typeof RESEND_BLOCK]>
) {
  return (
    encodeCredential(credential) + OTP_SEPARATOR +
    compressNumber(expires) + OTP_SEPARATOR +
    otp + OTP_SEPARATOR +
    getEnvOtpMaxAttempts(c) + OTP_SEPARATOR +
    compressNumber(resendBlock)
  );
}

/**
 * @function decodeOtpToken
 * @param {string} encodedOtpToken
 * @returns {OtpToken|undefined} If it doesn't return anything, it means the token is invalid, and maybe the keys were compromised.
 */
export function decodeOtpToken(encodedOtpToken: string): OtpToken | undefined {
  const otpToken: any = encodedOtpToken.split(OTP_SEPARATOR);

  otpToken[EXPIRES] = decompressNumber(otpToken[EXPIRES]);

  try {
    otpToken[CREDENTIAL] = decodeCredential(otpToken[CREDENTIAL]);
  } catch {
    return;
  }

  if (!otpToken[CREDENTIAL]) {
    return;
  }

  if (otpToken[OTP]) {
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS];
    /**
     * `otpToken[ATTEMPTS]` can't be zero because it's automatically deleted.
     */
    if (isNaN(otpToken[ATTEMPTS]) || otpToken[ATTEMPTS] <= 0) {
      return;
    }

    if (otpToken[RESEND_BLOCK]) {
      otpToken[RESEND_BLOCK] = decompressNumber(otpToken[RESEND_BLOCK]);
    }

    if (otpToken[OTP_BLOCK]) {
      otpToken[OTP_BLOCK] = decompressNumber(otpToken[OTP_BLOCK]);
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

export function generateOtp(c: Context): string {
  const OTP_LENGTH = getEnvOtpLength(c);

  return (
    crypto.getRandomValues(new BigUint64Array(1))[0]
      .toString(getEnvOtpRadix(c))
      .substring(0, OTP_LENGTH)
      .padStart(OTP_LENGTH, "0")
  );
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
