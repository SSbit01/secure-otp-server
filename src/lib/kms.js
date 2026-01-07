import { getCurrentKekId, storeKek } from "@/custom/kms"

import { createKek } from "@/lib/crypto/symmetric/kek"
import { createRandomIdString } from "@/lib/crypto/id"
import { deleteOtpCookie } from "@/lib/otp/cookie"


/**
 * @import { Context } from "hono"
 */


/**
 * @type {number}
 */
export const KEK_ID_BYTES = 12


/**
 * @function rotateKek
 * @param {Context} c
 * @param {string} kekId
 */
export async function rotateKek(c, kekId) {

  const currentKekId = await getCurrentKekId(c)

  if (!currentKekId || kekId === currentKekId) {
    console.warn("A KEK rotation has been triggered.")
    deleteOtpCookie(c)
    await storeKek(c, await createKek(), createRandomIdString(KEK_ID_BYTES))
    console.log("KEK rotation completed.")
  }

}