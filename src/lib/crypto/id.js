import base64ToBytes from "@/lib/base64"


/**
 * This implementation generates a cryptographically secure 144-bit random value, encoded in Base64 for a fixed 24-character output.
 * 
 * - Offers higher entropy than UUIDv4 (144 bits vs. 122 bits).
 * - Collision probability is lower than UUIDv4, though not zero.
 * - Of course possibility of collision still exist, even if it is lower than UUIDv4.
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @returns {string} A random ID.
 */
export default function createRandomID() {
  return base64ToBytes.encode(crypto.getRandomValues(new Uint8Array(18)))
}