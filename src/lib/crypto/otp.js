import createRandomId from "@/lib/crypto/id"
import { createSymmetricKey, encryptSymmetricallyText, decryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { textEncoder, textDecoder } from "@/lib/text"

import { doesEncryptionKeyExist, storeEncryptionKey, getEncryptionKey, deleteEncryptionKey } from "@/custom/kms"

/**
 * @import { Context } from "hono"
 */


/**
 * @async
 * @function encryptOtp
 * @param {Context} c
 * @param {string} value
 * @param {number} expires
 * @returns {Promise<[result:string,keyId:string]>}
 */
export async function encryptOtp(c, value, expires) {

  const key = await createSymmetricKey()

  const result = await encryptSymmetricallyText(
    key,
    value,
    textEncoder
  )

  let keyId
  
  do {
    keyId = createRandomId()
  } while (await doesEncryptionKeyExist(c, keyId))

  await storeEncryptionKey(c, keyId, key, expires)

  return [result, keyId]

}


/**
 * @async
 * @function decryptOtp
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<string|undefined>}
 */
export async function decryptOtp(c, keyId, token) {

  const key = await getEncryptionKey(c, keyId)

  if (!key) {
    return
  }

  /**
   * Fire and forget
   */
  deleteEncryptionKey(c, keyId)

  return await decryptSymmetricallyText(
    key,
    token,
    textDecoder
  )

}