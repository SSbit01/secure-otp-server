import { decryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { textDecoder } from "@/lib/text"

import { getEncryptionKey } from "@/custom/kms"

/**
 * @import { Context } from "hono"
 */


/**
 * @async
 * @function decryptOtp
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<string|undefined>}
 * @throws {TypeError} Thrown if `token` is not a string.
 * @throws {SyntaxError} Thrown if `token` contains characters outside Base64 alphabet.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptOtp(c, keyId, token) {

  const key = await getEncryptionKey(c, keyId)

  if (!key) {
    return
  }

  return await decryptSymmetricallyText(
    key,
    token,
    textDecoder
  )

}