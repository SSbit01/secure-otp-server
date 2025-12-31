import { getCookie } from "hono/cookie"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { updateOtpTokenExpires } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { createOtp, OTP_ALLOW_ONLY_ONE_RESENDING, OTP_MAX_ATTEMPTS } from "@/custom/otp"
import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { KEK_ID_BYTES, KEK_ID_LENGTH, createRandomIdString } from "@/lib/crypto/id"
import { encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { WRAPPED_DEK_BYTES, createKek, wrapKey, unwrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_OTP_EXPIRED,
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import { rotateKek } from "@/lib/kms"

import { createEncryptedOtpTokenList, getOtpTokenList, getOtpTokenData } from "@/lib/otp"
import { deleteOtpCookie, getOtpCookieName, setOtpCookie } from "@/lib/otp/cookie"
import { CREDENTIAL, EXPIRES, OTP, RESEND_BLOCK, OTP_BLOCK, decodeOtpToken, encodeOtpToken, createEncodedOtpToken } from "@/lib/otp/encode/token"

import { textEncoder } from "@/lib/text"
import { isLessThanDelay, getReducedTimePrecision } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import app from "@/setup"

import type { OtpTokenData } from "@/lib/otp"



const METADATA_STRING_LENGTH = KEK_ID_LENGTH + Math.ceil(WRAPPED_DEK_BYTES / 3) * 4  // Because of Base64 padding.



app.post("/api/otp/create", credentialValidator, async (c) => {

  const credential = c.req.valid("json")

  const encryptedOtpData = getCookie(c, getOtpCookieName(c))

  if (!encryptedOtpData) {
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  let kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH), BASE64URL_OPTIONS)

  const wrappedDek: Uint8Array<ArrayBuffer> | ArrayBuffer = otpData.subarray(0, WRAPPED_DEK_BYTES)

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(WRAPPED_DEK_BYTES))

  if (!encodedOtpTokenList || !encodedOtpTokenList.length) {
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  const lastAccessString = encodedOtpTokenList.pop()

  const id = encodedOtpTokenList.pop()

  if (!lastAccessString || !id || !encodedOtpTokenList.length || encodedOtpTokenList.length > OTP_MAX_ATTEMPTS) {
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const newEncodedOtpTokenList = []

  let currentOtpTokenData: OtpTokenData | undefined
  
  let currentEncodedOtpToken = ""
  let expires = 0
  let dateNow = Date.now()

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

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  if (!expires) {
    // All OTP tokens have expired, create a new list.
    return c.json(await createEncryptedOtpTokenList(c, credential))
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let metadata: string

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId === kekId) {
      metadata = encryptedOtpData.substring(0, METADATA_STRING_LENGTH)
    } else {
      kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    kek = await createKek()
    await storeKek(c, kek, kekId)
    metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
  }

  if (!currentEncodedOtpToken) {
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
    await sendOtp(c, credential, otp)
    dateNow = Date.now()
    const resendBlock = dateNow + OTP_RESEND_BLOCK_MS
    currentEncodedOtpToken = createEncodedOtpToken(credential, expires, otp, resendBlock)
    currentOtpTokenData = {
      expires: new Date(getReducedTimePrecision(expires)),
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    }
  }

  newEncodedOtpTokenList.push(
    currentEncodedOtpToken,
    id,
    compressNumber(dateNow)
  )

  setOtpCookie(
    c,
    (
      metadata +
      await encryptTextSymmetrically(
        dek,
        newEncodedOtpTokenList.join(","),
        textEncoder
      )
    ),
    currentOtpTokenData?.expires
  )
  
  return c.json(currentOtpTokenData)

})


app.post("/api/otp/resend", otpCookieValidator, async (c) => {

  const encryptedOtpData = getCookie(c, getOtpCookieName(c))

  if (!encryptedOtpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH), BASE64URL_OPTIONS)

  const wrappedDek: Uint8Array<ArrayBuffer> | ArrayBuffer = otpData.subarray(0, WRAPPED_DEK_BYTES)

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(WRAPPED_DEK_BYTES))

  if (!encodedOtpTokenList || !encodedOtpTokenList.length) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccessString = encodedOtpTokenList.pop()
  const id = encodedOtpTokenList.pop()
  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")

  if (!lastAccessString || !id || !currentOtpToken || encodedOtpTokenList.length >= OTP_MAX_ATTEMPTS) {
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const newEncodedOtpTokenList = []
  
  let expires = currentOtpToken[EXPIRES]
  let dateNow = Date.now()

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken)
    if (!otpToken) {
      await rotateKek(c, kekId)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
      newEncodedOtpTokenList.push(encodeOtpToken(otpToken))
    }
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (dateNow >= currentOtpToken[EXPIRES]) {
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  if (currentOtpToken[RESEND_BLOCK] && dateNow < currentOtpToken[RESEND_BLOCK]) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let metadata: string

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId === kekId) {
      metadata = encryptedOtpData.substring(0, METADATA_STRING_LENGTH)
    } else {
      kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    kek = await createKek()
    await storeKek(c, kek, kekId)
    metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
  }

  expires = await updateOtpTokenExpires(c, id, expires)

  if (!expires) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  currentOtpToken[EXPIRES] = expires

  currentOtpToken[OTP] = createOtp()

  await sendOtp(c, currentOtpToken[CREDENTIAL], currentOtpToken[OTP])

  dateNow = Date.now()

  if (OTP_ALLOW_ONLY_ONE_RESENDING) {
    delete currentOtpToken[RESEND_BLOCK]
  } else {
    currentOtpToken[RESEND_BLOCK] = dateNow + OTP_RESEND_BLOCK_MS
  }

  newEncodedOtpTokenList.push(
    encodeOtpToken(currentOtpToken),
    id,
    compressNumber(dateNow)
  )

  const currentOtpTokenData = getOtpTokenData(currentOtpToken)

  setOtpCookie(
    c,
    (
      metadata +
      await encryptTextSymmetrically(
        dek,
        newEncodedOtpTokenList.join(","),
        textEncoder
      )
    ),
    currentOtpTokenData.expires
  )
  
  return c.json(currentOtpTokenData)

})


app.post("/api/otp/verify", otpValueValidator, async (c) => {

  const encryptedOtpData = getCookie(c, getOtpCookieName(c))

  if (!encryptedOtpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH), BASE64URL_OPTIONS)

  const wrappedDek: Uint8Array<ArrayBuffer> | ArrayBuffer = otpData.subarray(0, WRAPPED_DEK_BYTES)

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(WRAPPED_DEK_BYTES))

  if (!encodedOtpTokenList || !encodedOtpTokenList.length) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccessString = encodedOtpTokenList.pop()
  const id = encodedOtpTokenList.pop()
  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")

  if (!lastAccessString || !id || !currentOtpToken || encodedOtpTokenList.length >= OTP_MAX_ATTEMPTS) {
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const newEncodedOtpTokenList = []
  
  let expires = currentOtpToken[EXPIRES]
  let dateNow = Date.now()

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken)
    if (!otpToken) {
      await rotateKek(c, kekId)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
      newEncodedOtpTokenList.push(encodeOtpToken(otpToken))
    }
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (dateNow >= currentOtpToken[EXPIRES]) {
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  /**
   * [OTP_BLOCK] already filtered in `decodeOtpString`.
   */
  if (currentOtpToken[OTP_BLOCK]) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  if (currentOtpToken[OTP] === c.req.valid("form")) {
    deleteOtpCookie(c)
    return await deleteId(c, id, expires) ? await finalAction(c, currentOtpToken[CREDENTIAL]) : undefined
  }

  // @ts-expect-error: `#idValid` is true.
  const id = await replaceId(this.#context, this.#id, this.#expires)

  if (!id) {
    deleteOtpCookie(this.#context)
    return
  }

  this.#id = id

  // @ts-expect-error: `#current` is defined.
  this.#current[ATTEMPTS]--

  const attempts = this.#current?.[ATTEMPTS]

  if (!attempts) {
    /** Trim the array to save space. */
    // @ts-expect-error: `#current` and `#idValid` are not falsy.
    this.#current.length = OTP
  } else if (OTP_INVALID_BLOCK_MS && attempts <= OTP_ATTEMPTS_BLOCK) {
    const otpBlock = Date.now() + OTP_INVALID_BLOCK_MS
    otpBlock >= (this.#current[EXPIRES] - 1000)
      ? this.#current.length = OTP
      : this.#current[OTP_BLOCK] = otpBlock
  } else {
    /** Trim the array to save space. */
    this.#current.length = OTP_BLOCK
  }

  // const credential = await otpTokenList.check(c.req.valid("form"))

  // if (credential) {
  //   /**
  //    * VERIFIED
  //    */
  //   return await finalAction(c, credential)
  // }

  // if (otpTokenList.blocked) {
  //   return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)
  // }

  // const otpBlock = otpTokenList.otpBlock

  // if (otpBlock) {
  //   return c.json({
  //     ...ERR_OTP_INCORRECT,
  //     otpBlock: otpBlock
  //   }, 400)
  // }

  // return c.json(ERR_OTP_INCORRECT, 400)

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let metadata: string

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId === kekId) {
      metadata = encryptedOtpData.substring(0, METADATA_STRING_LENGTH)
    } else {
      kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    kek = await createKek()
    await storeKek(c, kek, kekId)
    metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
  }

  expires = await updateOtpTokenExpires(c, id, expires)

  if (!expires) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  currentOtpToken[EXPIRES] = expires

  currentOtpToken[OTP] = createOtp()

  await sendOtp(c, currentOtpToken[CREDENTIAL], currentOtpToken[OTP])

  dateNow = Date.now()

  if (OTP_ALLOW_ONLY_ONE_RESENDING) {
    delete currentOtpToken[RESEND_BLOCK]
  } else {
    currentOtpToken[RESEND_BLOCK] = dateNow + OTP_RESEND_BLOCK_MS
  }

  newEncodedOtpTokenList.push(
    encodeOtpToken(currentOtpToken),
    id,
    compressNumber(dateNow)
  )

  const currentOtpTokenData = getOtpTokenData(currentOtpToken)

  setOtpCookie(
    c,
    (
      metadata +
      await encryptTextSymmetrically(
        dek,
        newEncodedOtpTokenList.join(","),
        textEncoder
      )
    ),
    currentOtpTokenData.expires
  )
  
  return c.json(currentOtpTokenData)

})



export default app