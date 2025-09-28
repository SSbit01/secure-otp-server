import { createSymmetricKey, encryptSymmetricallyText, decryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { storeEncryptionKey, getEncryptionKey } from "@/custom/kms"

import type { Context } from "hono"


const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()


export async function encryptOtp(c: Context, keyID: string, value: string, expires: number) {

  const key = await createSymmetricKey()

  const result = await encryptSymmetricallyText(
    value,
    key,
    textEncoder
  )

  await storeEncryptionKey(c, keyID, key, expires)

  return result

}


export async function decryptOtp(c: Context, keyID: string, value: string) {

  const key = await getEncryptionKey(c, keyID)

  return key && await decryptSymmetricallyText(
    value,
    key,
    textDecoder
  )

}