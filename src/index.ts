import { getCookie } from "hono/cookie"

import app from "@/setup"

import { isRandomIdValid } from "@/lib/crypto/id"
import { ERR_OTP_BLOCKED, ERR_OTP_RESENT_NOT_ALLOWED, ERR_OTP_TOO_MANY_ATTEMPTS, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { OTP_INCORRECT } from "@/lib/error/names"
import { COOKIE_KEY_ID, COOKIE_OTP, createOtpAndSend, getOtpInstance } from "@/lib/otp"

import otpCookieValidator from "@/lib/validators/cookie"
import otpValueValidator from "@/lib/validators/otp"

import credentialValidator from "@/custom/credential"
import { deleteEncryptionKey } from "@/custom/kms"
import { ALLOW_ONLY_ONE_RESENDING, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS } from "@/custom/otp"
import finalAction from "@/custom/final"



interface ResponseOtpIncorrect {
  error: typeof OTP_INCORRECT
  message: string
  blockedUntil?: number
}



app.post("/api/otp/create", credentialValidator, async(c) => {

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token } = getCookie(c)

  const credential = c.req.valid("json")

  if (!keyId || !isRandomIdValid(keyId) || !token) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }
  
  // credential:otp:attempts:expires:resendBlockDate:otpBlockDate(optional)
  const otpTokenList = await getOtpInstance(c, keyId, token)

  switch (otpTokenList) {
    case false:
      return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
    case undefined:
      return c.json(await createOtpAndSend(c, credential))
  }

  

  const dateNow = Date.now()

  if (storedCredential !== credential) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  if (!resendBlockDate || dateNow < +resendBlockDate) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

})



app.post("/api/otp/resend", otpCookieValidator, async(c) => {
    
  // credential:otp:attempts:expires:resendBlockDate:otpBlockDate(optional)
  const [, resendBlockDate, credential] = c.req.valid("cookie")

  if (!resendBlockDate || Date.now() < +resendBlockDate) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

})



app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  // credential:otp:attempts:expires:resendBlockDate:otpBlockDate(optional)
  const [expires, resendBlockDate, credential, otpValid, attempts, otpBlockDate] = c.req.valid("cookie")


  if (otpBlockDate) {

    const timeDifference = (+otpBlockDate) - Date.now()

    if (timeDifference > 0) {
      return c.json(ERR_OTP_BLOCKED, 400)
    }

  }

  
  if (otpValid !== c.req.valid("form")) {

    const currentAttempts = +attempts - 1

    /**
     * Is `currentAttempts` 0?
     */
    if (!currentAttempts) {
      return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)  // User has to log in again
    }

    const res: ResponseOtpIncorrect = {
      error: OTP_INCORRECT,
      message: "Incorrect OTP value"
    }

    let newOtpDateBlocked = 0

    const dateNow = Date.now()

    if (INVALID_BLOCK_MS && currentAttempts <= ATTEMPTS_BLOCK) {
      newOtpDateBlocked = dateNow + INVALID_BLOCK_MS
      res.blockedUntil = newOtpDateBlocked
    }

    await createOtpCookie(c, credential, otpValid, expires, dateNow, resendBlockDate, currentAttempts, newOtpDateBlocked)

    return c.json(res, 400)

  }

  
  return await finalAction(c, decodeURIComponent(credential))

})



export default app