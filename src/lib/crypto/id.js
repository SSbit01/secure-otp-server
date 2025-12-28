import { BASE64URL_OPTIONS } from "@/lib/base64"


const BYTES_BASE64_RATIO = 4 / 3


/**
 * @type {number}
 */
export const KEK_ID_BYTES = 12

/**
 * @type {number}
 */
export const KEK_ID_LENGTH = KEK_ID_BYTES * BYTES_BASE64_RATIO


/**
 * - Offers higher entropy than UUIDv4 (144 bits vs 122 bits).
 * - Collision probability is much lower than UUIDv4, though not zero (2⁻¹⁴⁴ < 2⁻¹²²).
 * 
 * @type {number}
 */
export const OTP_ID_BYTES = 18

/**
 * @type {number}
 */
export const OTP_ID_LENGTH = OTP_ID_BYTES * BYTES_BASE64_RATIO


/**
 * This implementation generates a cryptographically secure 144-bit length random value by default.
 * 
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @function createRandomId
 * @param {number} [length] - The length of the ID to generate.
 * @returns {Uint8Array<ArrayBuffer>} A random ID.
 */
export function createRandomId(length = OTP_ID_BYTES) {
  return crypto.getRandomValues(new Uint8Array(length))
}


/**
 * @function createRandomIdString
 * @param {number} [length] - The length of the ID to generate.
 * @returns {string} A string random ID.
 */
export function createRandomIdString(length = OTP_ID_BYTES) {
  return createRandomId(length).toBase64(BASE64URL_OPTIONS)
}