import {
  createSymmetricKey,
  createSymmetricKeyWithText,
  encryptSymmetricallyText,
  decryptSymmetricallyText
} from "./index.js"

import type { Context } from "hono"


const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()


let otpKeyObject: CryptoKey


async function getOtpKey(
  c: Context
) {

  if (!otpKeyObject) {
    const { OTP_KEY } = env(c)
    if (!OTP_KEY) {
      throw new Error(
        "Required environment variable `OTP_KEY` is not set or is empty."
      )
    }
    otpKeyObject = await createSymmetricKeyWithText(
      OTP_KEY,
      textEncoder
    )
  }

  return otpKeyObject

}


export async function encryptOtp(
  c: Context,
  value: string
) {

  return await encryptSymmetricallyText(
    value,
    await getOtpKey(c),
    textEncoder
  )

}


export async function decryptOtp(
  c: Context,
  value: string
) {

  return await decryptSymmetricallyText(
    value,
    await getOtpKey(c),
    textDecoder
  )

}