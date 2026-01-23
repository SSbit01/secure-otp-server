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
import { KEK_ID_LENGTH } from "@/lib/computed"
import { createRandomIdString } from "@/lib/crypto/id"
import { encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
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

import {
  ENVELOPE_ENCRYPTION_WRAP_LENGTH,
  OTP_INVALID_BLOCK_MS,
  OTP_RESEND_BLOCK_MS
} from "@/lib/computed"

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

  const dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!dek) {
    return await generateOtpTokenCreationResponse(c, credential)
  }

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!encodedOtpTokenList) {
    return await generateOtpTokenCreationResponse(c, credential)
  }

  const id = encodedOtpTokenList.pop()

  if (!id || encodedOtpTokenList.length > OTP_MAX_CREDENTIALS) {
    await rotateKek(c, kekId)
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
      await rotateKek(c, kekId)
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

  if (currentKekId) {
    if (currentKekId === kekId) {
      envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
    } else {
      let kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    const kek = await createKek()
    await storeKek(c, kek, kekId)
    envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
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

  const {
    currentOtpToken,
    dek,
    encodedOtpTokenList,
    expires,
    id,
    envelope
  } = c.req.valid("cookie")

  if (currentOtpToken[RESEND_BLOCK] && Date.now() < currentOtpToken[RESEND_BLOCK]) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  currentOtpToken[EXPIRES] = await updateOtpTokenExpires(c, id, expires)

  if (!currentOtpToken[EXPIRES]) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  currentOtpToken[OTP] = createOtp()

  if (!await sendOtp(c, currentOtpToken[CREDENTIAL], currentOtpToken[OTP])) {
    /**
     * Block the OTP token.
     */
    blockOtpToken(currentOtpToken)
  } else if (OTP_ALLOW_ONLY_ONE_RESENDING) {
    delete currentOtpToken[RESEND_BLOCK]
  } else {
    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS
    if ((currentOtpToken[EXPIRES] - resendBlock) > 4000) {
      currentOtpToken[RESEND_BLOCK] = resendBlock
    }
  }

  encodedOtpTokenList.push(
    encodeOtpToken(currentOtpToken),
    id
  )

  const currentOtpTokenData = getOtpTokenData(currentOtpToken)

  setOtpCookie(
    c,
    (
      envelope +
      await encryptTextSymmetrically(
        dek,
        encodeOtpTokenList(encodedOtpTokenList)
      )
    ),
    currentOtpTokenData.expires
  )

  return currentOtpTokenData.blocked
    ? c.json(ERR_CREDENTIAL_INVALID, 400)
    : c.json(currentOtpTokenData)

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async (c) => {

  const {
    currentOtpToken,
    dek,
    encodedOtpTokenList,
    expires,
    id,
    envelope
  } = c.req.valid("cookie")

  /**
   * [OTP_BLOCK] already filtered in `decodeOtpString`.
   */
  if (currentOtpToken[OTP_BLOCK] || !currentOtpToken[ATTEMPTS]) {
    return c.json(ERR_OTP_VERIFICATION_NOT_ALLOWED, 403)
  }

  if (currentOtpToken[OTP] === c.req.valid("form")) {
    deleteOtpCookie(c)
    return await deleteOtpTokenId(c, id, expires)
      ? await finalAction(c, currentOtpToken[CREDENTIAL])
      : c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const newId = await replaceOtpTokenId(c, id, expires)

  if (!newId) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  currentOtpToken[ATTEMPTS]--

  if (!currentOtpToken[ATTEMPTS]) {
    blockOtpToken(currentOtpToken)
  } else if (OTP_INVALID_BLOCK_MS && currentOtpToken[ATTEMPTS] <= OTP_ATTEMPTS_BLOCK) {
    currentOtpToken[OTP_BLOCK] = Date.now() + OTP_INVALID_BLOCK_MS
    /**
     * If the OTP block time is greater than or similar to the OTP expiration time, block the OTP.
     */
    if ((currentOtpToken[EXPIRES] - currentOtpToken[OTP_BLOCK]) <= 1000) {
      blockOtpToken(currentOtpToken)
    }
  }

  encodedOtpTokenList.push(
    encodeOtpToken(currentOtpToken),
    newId
  )

  setOtpCookie(
    c,
    (
      envelope +
      await encryptTextSymmetrically(
        dek,
        encodeOtpTokenList(encodedOtpTokenList)
      )
    ),
    new Date(getReducedTimePrecision(expires))
  )

  const currentOtpTokenData = getOtpTokenData(currentOtpToken)

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