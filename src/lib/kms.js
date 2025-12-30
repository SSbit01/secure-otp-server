import { getCurrentKekId, storeKek } from "@/custom/kms"

import { createKek } from "@/lib/crypto/symmetric/kek"
import { KEK_ID_BYTES, createRandomIdString } from "@/lib/crypto/id"
import { deleteOtpCookie } from "@/lib/otp/cookie"


/**
 * @import { Context } from "hono"
 */


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
    await storeKek(c, await createKek(), await createRandomIdString(KEK_ID_BYTES))
    console.log("KEK rotation completed.")
  }

}