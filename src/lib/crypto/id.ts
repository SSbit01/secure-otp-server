/**
 * This implementation generates a cryptographically secure 96-bit length random value by default.
 *
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 *
 * @param length - The length of the ID to generate (18 by default; higher entropy than UUIDv4 [122 vs 144 bits]).
 */
export function generateRandomId(length = 18): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}
