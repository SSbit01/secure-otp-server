import { otpMaxDurationSeconds } from "./otp.js"

import type { Context } from "hono"



const keyStorage = new Map<string, {
  key: CryptoKey
  expires: Date | number
}>()



export async function storeEncryptionKey(c: Context, keyId: string, key: CryptoKey, expires: number) {

  keyStorage.set(keyId, { key, expires })

}


export async function getEncryptionKey(c: Context, keyId: string): Promise<CryptoKey | undefined> {

  return keyStorage.get(keyId)?.key

}


export async function deleteEncryptionKey(c: Context, keyId: string) {

  keyStorage.delete(keyId)
  
}