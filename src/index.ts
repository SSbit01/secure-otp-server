import { getCookie } from "hono/cookie"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { deleteOtpTokenId, replaceOtpTokenId, updateOtpTokenExpires } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"

import {
  OTP_ALLOW_ONLY_ONE_RESENDING,
  OTP_ATTEMPTS_BLOCK,
  OTP_MAX_CREDENTIALS,
  createOtp
} from "@/custom/otp"

import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH, OTP_INVALID_BLOCK_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { createRandomIdString } from "@/lib/crypto/id"
import { createDek, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_CREDENTIAL_INVALID,
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_CREDENTIALS,
  ERR_OTP_VERIFICATION_NOT_ALLOWED
} from "@/lib/error/static"

import { KEK_ID_BYTES, getDek, rotateKek } from "@/lib/kms"
import { blockOtpToken, getOtpTokenList, getOtpTokenData } from "@/lib/otp"
import { deleteOtpCookie, getOtpCookieName, setOtpCookie } from "@/lib/otp/cookie"

import {
  CREDENTIAL,
  EXPIRES,
  OTP,
  ATTEMPTS,
  RESEND_BLOCK,
  OTP_BLOCK,
  createEncodedOtpToken,
  decodeOtpToken,
  encodeOtpToken,
  encodeOtpTokenList
} from "@/lib/otp/encode/token"

import generateOtpTokenCreationResponse from "./lib/otp/response/create"
import { getReducedTimePrecision } from "@/lib/time"
import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import app from "@/setup"

import type { OtpTokenData } from "@/lib/otp"



app.post("/api/otp/create", credentialValidator, async (c) => {

  const credential = c.req.valid("json")

  const otpData = getCookie(c, getOtpCookieName(c))?.trim()

  if (!otpData) {
    return await generateOtpTokenCreationResponse(c, credential)
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  let dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!dek) {
    return await generateOtpTokenCreationResponse(c, credential)
  }

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!encodedOtpTokenList) {
    return await generateOtpTokenCreationResponse(c, credential)
  }

  const id = encodedOtpTokenList.pop()

  if (!id) {
    deleteOtpCookie(c)
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  if (encodedOtpTokenList.length > OTP_MAX_CREDENTIALS) {
    deleteOtpCookie(c)
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)])
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const newEncodedOtpTokenList: string[] = []

  let currentOtpTokenData: OtpTokenData | undefined
  let currentEncodedOtpToken = ""
  let expires = 0

  const dateNow = Date.now()

  for (let encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken)
    if (!otpToken) {
      deleteOtpCookie(c)
      await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)])
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
      encodedOtpToken = encodeOtpToken(otpToken)
      if (!currentEncodedOtpToken && credential === otpToken[CREDENTIAL]) {
        currentEncodedOtpToken = encodedOtpToken
        currentOtpTokenData = getOtpTokenData(otpToken)
      } else {
        newEncodedOtpTokenList.push(encodedOtpToken)
      }
    }
  }

  if (newEncodedOtpTokenList.length >= OTP_MAX_CREDENTIALS) {
    return c.json(ERR_OTP_TOO_MANY_CREDENTIALS, 400)
  }

  if (!expires) {
    // All OTP tokens have expired, create a new list.
    return await generateOtpTokenCreationResponse(c, credential)
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let envelope: string

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId === kekId) {
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
  } else {
    /**
     * @type {(CryptoKey|undefined)}
     */
    let kek
    if (currentKekId) {
      [dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)])
    } else {
      dek = await createDek()
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      kekId = currentKekId
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    } else {
      kekId = createRandomIdString(KEK_ID_BYTES)
      kek = await createKek()
      envelope = (
        kekId +
        new Uint8Array((await Promise.all([wrapKey(dek, kek), storeKek(c, kek, kekId)]))[0]).toBase64(BASE64URL_OPTIONS)
      )
    }
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (currentEncodedOtpToken) {
    newEncodedOtpTokenList.push(currentEncodedOtpToken)
  } else {
    /**
     * `updateOtpTokenExpires` is used to verify too.
     * Verify OTP Token List ID before sending the OTP.
     */
    expires = await updateOtpTokenExpires(c, id, expires)
    if (!expires) {
      deleteOtpCookie(c)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    const otp = createOtp()
    if (!await sendOtp(c, credential, otp)) {
      return c.json(ERR_CREDENTIAL_INVALID, 400)
    }
    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS
    currentEncodedOtpToken = createEncodedOtpToken(credential, expires, otp, resendBlock)
    newEncodedOtpTokenList.push(currentEncodedOtpToken)
    currentOtpTokenData = {
      expires: new Date(getReducedTimePrecision(expires)),
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    }
  }

  newEncodedOtpTokenList.push(id)

  setOtpCookie(
    c,
    (
      envelope +
      await encryptTextSymmetrically(
        dek,
        encodeOtpTokenList(newEncodedOtpTokenList)
      )
    ),
    new Date(getReducedTimePrecision(expires))
  )

  return c.json(currentOtpTokenData)

})


app.post("/api/otp/resend", otpCookieValidator, async (c) => {

  const data = c.req.valid("cookie")

  if (data.currentOtpToken[RESEND_BLOCK] && Date.now() < data.currentOtpToken[RESEND_BLOCK]) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   * 
   * @type {string}
   */
  let envelope

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId === data.kekId) {
    envelope = data.otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
  } else {
    /**
     * @type {(CryptoKey|undefined)}
     */
    let kek
    if (currentKekId) {
      [data.dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)])
    } else {
      data.dek = await createDek()
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      data.kekId = currentKekId
      envelope = data.kekId + new Uint8Array(await wrapKey(data.dek, kek)).toBase64(BASE64URL_OPTIONS)
    } else {
      data.kekId = createRandomIdString(KEK_ID_BYTES)
      kek = await createKek()
      envelope = (
        data.kekId +
        new Uint8Array((await Promise.all([wrapKey(data.dek, kek), storeKek(c, kek, data.kekId)]))[0]).toBase64(BASE64URL_OPTIONS)
      )
    }
  }

  data.currentOtpToken[EXPIRES] = await updateOtpTokenExpires(c, data.id, data.expires)

  if (!data.currentOtpToken[EXPIRES]) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  data.currentOtpToken[OTP] = createOtp()

  if (!await sendOtp(c, data.currentOtpToken[CREDENTIAL], data.currentOtpToken[OTP])) {
    /**
     * Block the OTP token.
     */
    blockOtpToken(data.currentOtpToken)
  } else if (OTP_ALLOW_ONLY_ONE_RESENDING) {
    delete data.currentOtpToken[RESEND_BLOCK]
  } else {
    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS
    /**
     * Only set resend block if the OTP token will expire in more than 4 seconds.
     */
    if ((data.currentOtpToken[EXPIRES] - resendBlock) > 4000) {
      data.currentOtpToken[RESEND_BLOCK] = resendBlock
    }
  }

  data.encodedOtpTokenList.push(
    encodeOtpToken(data.currentOtpToken),
    data.id
  )

  const currentOtpTokenData = getOtpTokenData(data.currentOtpToken)

  setOtpCookie(
    c,
    (
      envelope +
      await encryptTextSymmetrically(
        data.dek,
        encodeOtpTokenList(data.encodedOtpTokenList)
      )
    ),
    currentOtpTokenData.expires
  )

  return currentOtpTokenData.blocked
    ? c.json(ERR_CREDENTIAL_INVALID, 400)
    : c.json(currentOtpTokenData)

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async (c) => {

  const data = c.req.valid("cookie")

  /**
   * [OTP_BLOCK] already filtered in `decodeOtpToken`.
   */
  if (data.currentOtpToken[OTP_BLOCK] || !data.currentOtpToken[ATTEMPTS]) {
    return c.json(ERR_OTP_VERIFICATION_NOT_ALLOWED, 403)
  }

  if (data.currentOtpToken[OTP] === c.req.valid("form")) {
    const otpTokenIdDeletion = await deleteOtpTokenId(c, data.id, data.expires)
    deleteOtpCookie(c)
    return otpTokenIdDeletion
      ? await finalAction(c, data.currentOtpToken[CREDENTIAL])
      : c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   * 
   * @type {string}
   */
  let envelope

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId === data.kekId) {
    envelope = data.otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
  } else {
    /**
     * @type {(CryptoKey|undefined)}
     */
    let kek
    if (currentKekId) {
      [data.dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)])
    } else {
      data.dek = await createDek()
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      data.kekId = currentKekId
      envelope = data.kekId + new Uint8Array(await wrapKey(data.dek, kek)).toBase64(BASE64URL_OPTIONS)
    } else {
      data.kekId = createRandomIdString(KEK_ID_BYTES)
      kek = await createKek()
      envelope = (
        data.kekId +
        new Uint8Array((await Promise.all([wrapKey(data.dek, kek), storeKek(c, kek, data.kekId)]))[0]).toBase64(BASE64URL_OPTIONS)
      )
    }
  }

  const newId = await replaceOtpTokenId(c, data.id, data.expires)

  if (!newId) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  data.currentOtpToken[ATTEMPTS]--

  if (!data.currentOtpToken[ATTEMPTS]) {
    blockOtpToken(data.currentOtpToken)
  } else if (OTP_INVALID_BLOCK_MS && data.currentOtpToken[ATTEMPTS] <= OTP_ATTEMPTS_BLOCK) {
    data.currentOtpToken[OTP_BLOCK] = Date.now() + OTP_INVALID_BLOCK_MS
    /**
     * If the OTP block time is greater than or similar to the OTP expiration time, block the OTP.
     */
    if ((data.currentOtpToken[EXPIRES] - data.currentOtpToken[OTP_BLOCK]) <= 1000) {
      blockOtpToken(data.currentOtpToken)
    }
  }

  data.encodedOtpTokenList.push(
    encodeOtpToken(data.currentOtpToken),
    newId
  )

  setOtpCookie(
    c,
    (
      envelope +
      await encryptTextSymmetrically(
        data.dek,
        encodeOtpTokenList(data.encodedOtpTokenList)
      )
    ),
    new Date(getReducedTimePrecision(data.expires))
  )

  const currentOtpTokenData = getOtpTokenData(data.currentOtpToken)

  if (currentOtpTokenData.blocked) {
    return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 403)
  }

  if (currentOtpTokenData.otpBlock) {
    return c.json({
      ...ERR_OTP_INCORRECT,
      otpBlock: currentOtpTokenData.otpBlock
    }, 403)
  }

  return c.json(ERR_OTP_INCORRECT, 403)

})



export default app