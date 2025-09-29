import { createSymmetricKey, encryptSymmetricallyText, decryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { storeEncryptionKey, getEncryptionKey } from "@/custom/kms"

/**
 * @import { Context } from "hono"
 */


const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()


/**
 * @async
 * @param   {Context}         c
 * @param   {string}          keyID
 * @param   {string}          value
 * @param   {number}          expires
 * @returns {Promise<string>}
 */
export async function encryptOtp(c, keyID, value, expires) {

  const key = await createSymmetricKey()

  const result = await encryptSymmetricallyText(
    value,
    key,
    textEncoder
  )

  await storeEncryptionKey(c, keyID, key, expires)

  return result

}


/**
 * @async
 * @param   {Context}                   c
 * @param   {string}                    keyID
 * @param   {string}                    value
 * @returns {Promise<string|undefined>}
 */
export async function decryptOtp(c, keyID, value) {

  const key = await getEncryptionKey(c, keyID)

  return key && await decryptSymmetricallyText(
    value,
    key,
    textDecoder
  )

}