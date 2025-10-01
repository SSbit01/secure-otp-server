import base64ToBytes from "@/lib/base64"


/**
 * This implementation generates a cryptographically secure 144-bit random value, encoded in Base64 for a fixed 24-character output.
 * 
 * - Offers higher entropy than UUIDv4 (144 bits vs 122 bits).
 * - Collision probability is much lower than UUIDv4, though not zero (2⁻¹⁴⁴ < 2⁻¹²²).
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @returns {string} A 24-character Base64-encoded random ID.
 */
export default function createRandomId() {
  return base64ToBytes.encode(crypto.getRandomValues(new Uint8Array(18)))
}