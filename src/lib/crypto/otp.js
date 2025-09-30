import createRandomID from "@/lib/crypto/id"
import { createSymmetricKey, encryptSymmetricallyText, decryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { textEncoder, textDecoder } from "@/lib/text"

import { doesEncryptionKeyExist, storeEncryptionKey, getEncryptionKey } from "@/custom/kms"

/**
 * @import { Context } from "hono"
 */


/**
 * @async
 * @param {Context} c
 * @param {string} value
 * @param {number} expires
 * @returns {Promise<[result:string,keyID:string]>}
 */
export async function encryptOtp(c, value, expires) {

  const key = await createSymmetricKey()

  const result = await encryptSymmetricallyText(
    value,
    key,
    textEncoder
  )

  let keyID
  
  do {
    keyID = createRandomID()
  } while (await doesEncryptionKeyExist(c, keyID))

  await storeEncryptionKey(c, keyID, key, expires)

  return [result, keyID]

}


/**
 * @async
 * @param {Context} c
 * @param {string} value
 * @param {string} keyID
 * @returns {Promise<string|undefined>}
 */
export async function decryptOtp(c, value, keyID) {

  const key = await getEncryptionKey(c, keyID)

  return key && await decryptSymmetricallyText(
    value,
    key,
    textDecoder
  )

}