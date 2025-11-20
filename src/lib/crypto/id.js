/** @type {Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0]} */
const options = {
  alphabet: "base64url"
}

const LENGTH_IN_BYTES = 18


/**
 * Each Base64 character is 6-bits. So the total length would be `lengthInBytes * 8 / 6`.
 */
const RANDOM_ID_LENGTH = LENGTH_IN_BYTES * 4 / 3

const PROFILE_PUBLIC_ID_REGEX = /[\w\+\\]+/


/**
 * @function isRandomIdValid
 * @param {string} id 
 * @returns {boolean} ID validity.
 */
export function isRandomIdValid(id) {
  return id.length === RANDOM_ID_LENGTH && PROFILE_PUBLIC_ID_REGEX.test(id)
}


/**
 * This implementation generates a cryptographically secure 144-bit random value, encoded in Base64 for a fixed 24-character output.
 * 
 * - Offers higher entropy than UUIDv4 (144 bits vs 122 bits).
 * - Collision probability is much lower than UUIDv4, though not zero (2⁻¹⁴⁴ < 2⁻¹²²).
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @function 
 * @returns {string} A 24-character Base64-encoded random ID.
 */
export function createRandomId() {
  return crypto.getRandomValues(new Uint8Array(LENGTH_IN_BYTES)).toBase64(options)
}