import { createOtpTokenListId } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { createRandomIdString } from "@/lib/crypto/id"
import { createDek, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"
import { ERR_CREDENTIAL_INVALID } from "@/lib/error/static"
import { KEK_ID_BYTES } from "@/lib/kms"
import { OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { setOtpCookie } from "@/lib/otp/cookie"
import { createEncodedOtpToken, encodeOtpTokenList } from "@/lib/otp/encode/token"
import { getReducedTimePrecision } from "@/lib/time"


/**
 * @import { Context } from "hono"
 */


/**
 * @async
 * @function generateOtpTokenCreationResponse
 * @param {Context} c
 * @param {string} credential
 * @return {Promise<Response|undefined>}
 */
export default async function generateOtpTokenCreationResponse(c, credential) {

  const otp = createOtp()
  
  if (!await sendOtp(c, credential, otp)) {
    return c.json(ERR_CREDENTIAL_INVALID, 400)
  }

  let kekId = await getCurrentKekId(c)

  /**
   * @type {(CryptoKey|undefined)}
   */
  let kek

  if (kekId) {
    kek = await getKek(c, kekId)
  }

  if (!kek || !kekId) {
    kek = await createKek()
    kekId = createRandomIdString(KEK_ID_BYTES)
    await storeKek(c, kek, kekId)
  }

  const dek = await createDek()
  const wrappedDekString = new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)

  const [id, expires] = await createOtpTokenListId(c)

  const lessPreciseExpiresDate = new Date(getReducedTimePrecision(expires))
  const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS

  setOtpCookie(
    c,
    kekId +
    wrappedDekString +
    await encryptTextSymmetrically(
      dek,
      encodeOtpTokenList([createEncodedOtpToken(credential, expires, otp, resendBlock), id]),
      Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)
    ),
    lessPreciseExpiresDate
  )

  return c.json({
    expires: lessPreciseExpiresDate,
    resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
  })

}