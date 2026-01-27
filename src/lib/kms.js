import { deleteKek, getCurrentKekId, getKek, storeKek } from "@/custom/kms"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { KEK_ID_LENGTH } from "@/lib/computed"
import { createRandomIdString } from "@/lib/crypto/id"
import { WRAPPED_DEK_BYTES, createKek, unwrapKey } from "@/lib/crypto/symmetric/kek"
import { deleteOtpCookie } from "@/lib/otp/cookie"
import { regexBase64Url } from "@/lib/regex"


/**
 * @import { Context } from "hono"
 */


/**
 * @type {number}
 */
export const KEK_ID_BYTES = 12


/**
 * @async
 * @function getDek
 * @param {Context} c
 * @param {string} kekId
 * @param {string} wrappedDekString
 * @returns {Promise<CryptoKey|undefined>}
 */
export async function getDek(c, kekId, wrappedDekString) {

  if (kekId.length !== KEK_ID_LENGTH || !regexBase64Url.test(kekId)) {
    return
  }

  const kek = await getKek(c, kekId)

  if (!kek) {
    return
  }

  /**
   * @type {Uint8Array<ArrayBuffer>}
   */
  let wrappedDek

  try {
    wrappedDek = Uint8Array.fromBase64(wrappedDekString, BASE64URL_OPTIONS)
  } catch {
    return
  }

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    return
  }

  return await unwrapKey(wrappedDek, kek)

}


/**
 * @function rotateKek
 * @param {Context} c
 * @param {string} kekId
 */
export async function rotateKek(c, kekId) {

  const currentKekId = await getCurrentKekId(c)

  if (!currentKekId || kekId === currentKekId) {
    console.warn("A KEK rotation has been triggered.")
    await storeKek(c, await createKek(), createRandomIdString(KEK_ID_BYTES))
    console.log("KEK rotation completed.")
  }

  await deleteKek(c, kekId)

}