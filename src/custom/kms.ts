import { otpMaxDurationSeconds } from "@/custom/otp"

import type { Context } from "hono"



const keyStorage = new Map<string, { key: CryptoKey; expires: Date | number }>()



export async function doesEncryptionKeyExist(c: Context, keyID: string) {

  return keyStorage.has(keyID)

}


export async function storeEncryptionKey(c: Context, keyID: string, key: CryptoKey, expires: number) {

  keyStorage.set(keyID, { key, expires })

}


export async function getEncryptionKey(c: Context, keyID: string): Promise<CryptoKey | undefined> {

  return keyStorage.get(keyID)?.key

}


export async function deleteEncryptionKey(c: Context, keyID: string) {

  keyStorage.delete(keyID)
  
}