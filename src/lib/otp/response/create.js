import { createEncryptedOtpTokenListId } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"

import { createOtp } from "@/custom/otp"

import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { compressNumber } from "@/lib/compression/number"
import { OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { createRandomIdString, KEK_ID_BYTES } from "@/lib/crypto/id"
import { createDek, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"
import { ERR_CREDENTIAL_INVALID } from "@/lib/error/static"
import { setOtpCookie } from "@/lib/otp/cookie"
import { createEncodedOtpToken } from "@/lib/otp/encode/token"

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

  if (!kek) {
    kek = await createKek()
    kekId = createRandomIdString(KEK_ID_BYTES)
    await storeKek(c, kek, kekId)
  }

  const dek = await createDek()
  const wrappedDekString = new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)

  const { id, expires } = await createEncryptedOtpTokenListId(c)

  const lessPreciseExpiresDate = new Date(getReducedTimePrecision(expires))
  const dateNow = Date.now()
  const resendBlock = dateNow + OTP_RESEND_BLOCK_MS

  setOtpCookie(
    c,
    kekId +
    wrappedDekString +
    await encryptTextSymmetrically(
      dek,
      createEncodedOtpToken(credential, expires, otp, resendBlock) + "," +
      id + "," +
      compressNumber(dateNow)
    ),
    lessPreciseExpiresDate
  )

  return c.json({
    expires: lessPreciseExpiresDate,
    resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
  }, 201)

}