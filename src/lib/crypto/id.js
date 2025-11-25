/** @type {Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0]} */
const options = {
  alphabet: "base64url"
}

const LENGTH_IN_BYTES = 18


/**
 * This implementation generates a cryptographically secure 144-bit length random value by default.
 * 
 * - Offers higher entropy than UUIDv4 (144 bits vs 122 bits).
 * - Collision probability is much lower than UUIDv4, though not zero (2⁻¹⁴⁴ < 2⁻¹²²).
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @function 
 * @param {number} [length] - The length of the random ID in bytes.
 * @returns {string} A random ID.
 */
export function createRandomId(length = LENGTH_IN_BYTES) {
  return crypto.getRandomValues(new Uint8Array(length)).toBase64(options)
}