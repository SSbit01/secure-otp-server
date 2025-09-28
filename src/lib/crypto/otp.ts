import { createSymmetricKey, encryptSymmetricallyText, decryptSymmetricallyText } from "@/lib/crypto"
import { storeEncryptionKey, getEncryptionKey } from "@/lib/custom/kms"

import type { Context } from "hono"


const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()


export async function encryptOtp(c: Context, keyId: string, value: string, expires: number) {

  const key = await createSymmetricKey()

  const result = await encryptSymmetricallyText(
    value,
    key,
    textEncoder
  )

  await storeEncryptionKey(c, keyId, key, expires)

  return result

}


export async function decryptOtp(c: Context, keyId: string, value: string) {

  const key = await getEncryptionKey(c, keyId)

  return key && await decryptSymmetricallyText(
    value,
    key,
    textDecoder
  )

}